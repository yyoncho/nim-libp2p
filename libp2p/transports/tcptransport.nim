## Nim-LibP2P
## Copyright (c) 2019 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

import std/[oids, sequtils, sugar]
import chronos, chronicles
import transport,
       ../errors,
       ../wire,
       ../multiaddress,
       ../multicodec,
       ../stream/connection,
       ../stream/chronosstream

logScope:
  topics = "tcptransport"

const
  TcpTransportTrackerName* = "libp2p.tcptransport"

type
  TcpTransport* = ref object of Transport
    server*: StreamServer
    clients: array[bool, seq[StreamTransport]]
    flags: set[ServerFlags]
    cleanups*: seq[Future[void]]

  TcpTransportTracker* = ref object of TrackerBase
    opened*: uint64
    closed*: uint64

proc setupTcpTransportTracker(): TcpTransportTracker {.gcsafe.}

proc getTcpTransportTracker(): TcpTransportTracker {.gcsafe.} =
  result = cast[TcpTransportTracker](getTracker(TcpTransportTrackerName))
  if isNil(result):
    result = setupTcpTransportTracker()

proc dumpTracking(): string {.gcsafe.} =
  var tracker = getTcpTransportTracker()
  result = "Opened tcp transports: " & $tracker.opened & "\n" &
           "Closed tcp transports: " & $tracker.closed

proc leakTransport(): bool {.gcsafe.} =
  var tracker = getTcpTransportTracker()
  result = (tracker.opened != tracker.closed)

proc setupTcpTransportTracker(): TcpTransportTracker =
  result = new TcpTransportTracker
  result.opened = 0
  result.closed = 0
  result.dump = dumpTracking
  result.isLeaked = leakTransport
  addTracker(TcpTransportTrackerName, result)

proc connHandler*(t: TcpTransport,
                  client: StreamTransport,
                  initiator: bool): Future[Connection] {.async, gcsafe.} =
  debug "Handling tcp connection", address = $client.remoteAddress,
                                   initiator = initiator,
                                   clients = t.clients[initiator].len

  let stream = ChronosStream.init(client,
                                  dir = if initiator: Direction.Out
                                  else: Direction.In)
  let conn = Connection(stream)
  conn.observedAddr = MultiAddress.init(client.remoteAddress).tryGet()

  proc onClose() {.async.} =
    try:
      await client.join()
      trace "cleaning up client", addrs = $client.remoteAddress,
                                  conn = $conn.oid
      if not(isNil(conn)):
        await conn.close()
      t.clients[initiator].keepItIf( it != client )
    except CatchableError as exc:
      let useExc {.used.} = exc
      trace "error cleaning up client", errMsg = exc.msg

  t.clients[initiator].add(client)
  asyncSpawn onClose()

  return conn

proc init*(
  T: type TcpTransport,
  flags: set[ServerFlags] = {},
  connMngr: ConnManager,
  upgrade: Upgrade): T =

  let t = T(
    flags: flags,
    upgrade: upgrade,
    connMngr: connMngr)

  t.initTransport()
  return t

method initTransport*(t: TcpTransport) =
  t.multicodec = multiCodec("tcp")
  inc getTcpTransportTracker().opened

method start*(t: TcpTransport, ma: MultiAddress) {.async.} =
  ## listen on the transport
  ##

  trace "Starting TCP transport", address = ma

  await procCall Transport(t).start(ma)
  t.server = createStreamServer(t.ma, t.flags, t)

  # always get the resolved address in case we're bound to 0.0.0.0:0
  t.ma = MultiAddress.init(t.server.sock.getLocalAddress()).tryGet()
  t.running = true

  trace "Listen started on", address = t.ma

method stop*(t: TcpTransport) {.async, gcsafe.} =
  ## stop the transport
  try:
    trace "Stopping TCP transport"
    await procCall Transport(t).stop() # call base

    checkFutures(
      await allFinished(
        t.clients[true].mapIt(it.closeWait()) &
        t.clients[false].mapIt(it.closeWait())))

    # server can be nil
    if not isNil(t.server):
      await t.server.closeWait()

    t.server = nil

    for fut in t.cleanups:
      if not fut.finished:
        fut.cancel()

    checkFutures(
      await allFinished(t.cleanups))
    t.cleanups = @[]

    trace "transport stopped"
    inc getTcpTransportTracker().closed
  except CatchableError as exc:
    let useExc {.used.} = exc
    trace "error shutting down tcp transport", errMsg = exc.msg
  finally:
    t.running = false

method accept*(t: TcpTransport) {.async, gcsafe.} =
  try:
    let transp = await t.server.accept()
    try:
      # we don't need result connection in this
      # case as it's added inside connHandler
      let conn = await t.connMngr.trackIncomingConn(
        () => t.connHandler(transp, false)
      )
      await t.upgrade.upgradeIncoming(conn)
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      let useExc {.used.} = exc
      debug "listen: connection setup failed", errMsg = exc.msg
      if not transp.closed:
        await transp.closeWait()
  except TransportTooManyError as exc:
    let useExc {.used.} = exc
    warn "listen: could not accept new client, too many files opened"
  except TransportOsError as exc:
    let useExc {.used.} = exc
    error "listen: could not accept new client, got an error",
          errMsg = exc.msg
    break
  except TransportUseClosedError as exc:
    let useExc {.used.} = exc
    info "Server was closed, exiting listening loop"
    break
  except CancelledError as exc:
    raise exc

method dial*(t: TcpTransport,
             peerId: PeerID,
             address: MultiAddress):
             Future[Connection] {.async, gcsafe.} =
  trace "dialing remote peer", address = $address
  ## dial a peer

  var conn: Connection
  try:
    # Check if we have a connection already and try to reuse it
    conn = await t.connMngr.getMuxedStream(peerId)
    if conn != nil:
      if conn.atEof or conn.closed:
        # This connection should already have been removed from the connection
        # manager - it's essentially a bug that we end up here - we'll fail
        # for now, hoping that this will clean themselves up later...
        warn "dead connection in connection manager", conn
        await conn.close()
        raise newException(DialFailedError, "Zombie connection encountered")

      trace "Reusing existing connection", conn, direction = $conn.dir
      return conn

    let transp = await connect(address)
    conn = await t.connMngr.trackOutgoingConn(
      () => t.connHandler(transp, initiator = true)
    )
    return await t.upgrade.upgradeOutgoing(conn)
  except TransportTooManyError as exc:
    warn "dial: could not create new connection, too many files opened"
    raise exc
  except TransportOsError as exc:
    debug "dial: could not create new connection, got an error",
         errMsg = exc.msg
    raise exc
  except CancelledError as exc:
    raise exc
  except CatchableError as exc:
    warn "dial: could not create new connection, unexpected error",
         errMsg = exc.msg
    raise exc

method handles*(t: TcpTransport, address: MultiAddress): bool {.gcsafe.} =
  if procCall Transport(t).handles(address):
    address.protocols.tryGet().filterIt( it == multiCodec("tcp") ).len > 0
  else:
    false
