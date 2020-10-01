## Nim-LibP2P
## Copyright (c) 2019 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

import std/[tables,
            sequtils,
            options,
            sets,
            oids,
            sugar]

import chronos,
       chronicles,
       metrics

import stream/connection,
       transports/transport,
       multistream,
       multiaddress,
       protocols/protocol,
       protocols/secure/secure,
       peerinfo,
       protocols/identify,
       muxers/muxer,
       utils/semaphore,
       connmanager,
       peerid,
       errors

export connmanager

logScope:
  topics = "switch"

#TODO: General note - use a finite state machine to manage the different
# steps of connections establishing and upgrading. This makes everything
# more robust and less prone to ordering attacks - i.e. muxing can come if
# and only if the channel has been secured (i.e. if a secure manager has been
# previously provided)

declareCounter(libp2p_dialed_peers, "dialed peers")
declareCounter(libp2p_failed_dials, "failed dials")

type
  Switch* = ref object of RootObj
    peerInfo*: PeerInfo
    connManager: ConnManager
    transports*: seq[Transport]
    protocols*: seq[LPProtocol]
    muxers*: Table[string, MuxerProvider]
    ms*: MultistreamSelect
    identity*: Identify
    streamHandler*: StreamHandler
    secureManagers*: seq[Secure]
    dialLock: Table[PeerID, AsyncLock]
    acceptFuts: seq[Future[void]]

proc addConnEventHandler*(s: Switch,
                          handler: ConnEventHandler,
                          kind: ConnEventKind) =
  s.connManager.addConnEventHandler(handler, kind)

proc removeConnEventHandler*(s: Switch,
                             handler: ConnEventHandler,
                             kind: ConnEventKind) =
  s.connManager.removeConnEventHandler(handler, kind)

proc addPeerEventHandler*(s: Switch,
                          handler: PeerEventHandler,
                          kind: PeerEvent) =
  s.connManager.addPeerEventHandler(handler, kind)

proc removePeerEventHandler*(s: Switch,
                             handler: PeerEventHandler,
                             kind: PeerEvent) =
  s.connManager.removePeerEventHandler(handler, kind)

proc disconnect*(s: Switch, peerId: PeerID) {.async, gcsafe.}

proc isConnected*(s: Switch, peerId: PeerID): bool =
  ## returns true if the peer has one or more
  ## associated connections (sockets)
  ##

  peerId in s.connManager

proc secure(s: Switch, conn: Connection): Future[Connection] {.async, gcsafe.} =
  if s.secureManagers.len <= 0:
    raise newException(UpgradeFailedError, "No secure managers registered!")

  let codec = await s.ms.select(conn, s.secureManagers.mapIt(it.codec))
  if codec.len == 0:
    raise newException(UpgradeFailedError, "Unable to negotiate a secure channel!")

  trace "Securing connection", conn, codec
  let secureProtocol = s.secureManagers.filterIt(it.codec == codec)

  # ms.select should deal with the correctness of this
  # let's avoid duplicating checks but detect if it fails to do it properly
  doAssert(secureProtocol.len > 0)

  return await secureProtocol[0].secure(conn, true)

proc disconnect*(s: Switch, peerId: PeerID): Future[void] {.gcsafe.} =
  s.connManager.dropPeer(peerId)

proc internalConnect(s: Switch,
                     peerId: PeerID,
                     addrs: seq[MultiAddress]): Future[Connection] {.async.} =
  if s.peerInfo.peerId == peerId:
    raise newException(CatchableError, "can't dial self!")

  var conn: Connection
  # Ensure there's only one in-flight attempt per peer
  let lock = s.dialLock.mgetOrPut(peerId, newAsyncLock())
  try:
    await lock.acquire()

    trace "Dialing peer", peerId
    for t in s.transports: # for each transport
      for a in addrs:      # for each address
        if t.handles(a):   # check if we can dial it
          trace "Dialing address", address = $a, peerId
          let dialed = try:
              await t.dial(a)
            except CancelledError as exc:
              trace "Dialing canceled", msg = exc.msg, peerId
              raise exc
            except CatchableError as exc:
              trace "Dialing failed", msg = exc.msg, peerId
              libp2p_failed_dials.inc()
              continue # Try the next address

          # make sure to assign the peer to the connection
          dialed.peerInfo = PeerInfo.init(peerId, addrs)

          libp2p_dialed_peers.inc()
          trace "Dial successful", conn, peerInfo = conn.peerInfo
          break
  finally:
    if lock.locked():
      lock.release()

  if isNil(conn): # None of the addresses connected
    raise newException(CatchableError, "Unable to establish outgoing link")

  if conn.closed():
    # This can happen if one of the peer event handlers deems the peer
    # unworthy and disconnects it
    raise newLPStreamClosedError()

  await s.connManager.triggerPeerEvents(peerId, PeerEvent.Joined)
  await s.connManager.triggerConnEvent(
    peerId, ConnEvent(kind: ConnEventKind.Connected, incoming: false))

  proc peerCleanup() {.async.} =
    try:
      await conn.join()
      await s.connManager.triggerConnEvent(
        peerId, ConnEvent(kind: ConnEventKind.Disconnected))
      await s.connManager.triggerPeerEvents(peerId, PeerEvent.Left)
    except CatchableError as exc:
      # This is top-level procedure which will work as separate task, so it
      # do not need to propagate CancelledError and should handle other errors
      warn "Unexpected exception in switch peer connect cleanup",
        conn, msg = exc.msg

  # All the errors are handled inside `cleanup()` procedure.
  asyncSpawn peerCleanup()

  trace "Opening stream", conn
  return await s.connManager.getMuxedStream(conn)

proc connect*(s: Switch, peerId: PeerID, addrs: seq[MultiAddress]) {.async.} =
  discard await s.internalConnect(peerId, addrs)

proc negotiateStream(s: Switch, conn: Connection, protos: seq[string]): Future[Connection] {.async.} =
  trace "Negotiating stream", conn, protos
  let selected = await s.ms.select(conn, protos)
  if not protos.contains(selected):
    await conn.closeWithEOF()
    raise newException(DialFailedError, "Unable to select sub-protocol " & $protos)

  return conn

proc dial*(s: Switch,
           peerId: PeerID,
           protos: seq[string]): Future[Connection] {.async.} =
  trace "Dialing (existing)", peerId, protos
  let stream = await s.connManager.getMuxedStream(peerId)
  if stream.isNil:
    raise newException(DialFailedError, "Couldn't get muxed stream")

  return await s.negotiateStream(stream, protos)

proc dial*(s: Switch,
           peerId: PeerID,
           proto: string): Future[Connection] = dial(s, peerId, @[proto])

proc dial*(s: Switch,
           peerId: PeerID,
           addrs: seq[MultiAddress],
           protos: seq[string]):
           Future[Connection] {.async.} =
  trace "Dialing (new)", peerId, protos
  var stream: Connection
  try:
    stream = await s.internalConnect(peerId, addrs)
    if not(isNil(stream)):
      return await s.negotiateStream(stream, protos)
  except CancelledError as exc:
    trace "Dial canceled", stream
    if not(isNil(stream)):
      await stream.closeWithEOF()

    raise exc
  except CatchableError as exc:
    debug "Error dialing", stream, msg = exc.msg
    if not(isNil(stream)):
      await stream.close()

    raise exc

proc dial*(s: Switch,
           peerId: PeerID,
           addrs: seq[MultiAddress],
           proto: string):
           Future[Connection] = dial(s, peerId, addrs, @[proto])

proc mount*[T: LPProtocol](s: Switch, proto: T) {.gcsafe.} =
  if isNil(proto.handler):
    raise newException(CatchableError,
      "Protocol has to define a handle method or proc")

  if proto.codec.len == 0:
    raise newException(CatchableError,
      "Protocol has to define a codec string")

  s.ms.addHandler(proto.codecs, proto)

proc accept(s: Switch, transport: Transport) {.async.} =
  ## transport's accept loop
  ##

  while transport.running:
    try:
      await transport.accept()
    except CancelledError as exc:
      trace "Canceling accept loop"
      break
    except CatchableError as exc:
      trace "Exception in accept loop", exc = exc.msg

proc start*(s: Switch): Future[seq[Future[void]]] {.async, gcsafe.} =
  trace "starting switch for peer", peerInfo = s.peerInfo
  var startFuts: seq[Future[void]]
  for t in s.transports: # for each transport
    for i, a in s.peerInfo.addrs:
      if t.handles(a): # check if it handles the multiaddr
        var server = t.start(a)
        s.peerInfo.addrs[i] = t.ma # update peer's address
        s.acceptFuts.add(s.accept(t))
        startFuts.add(server)

  debug "Started libp2p node", peer = s.peerInfo
  return startFuts # listen for incoming connections

proc stop*(s: Switch) {.async.} =
  trace "Stopping switch"

  for a in s.acceptFuts:
    if not a.finished:
      a.cancel()

  checkFutures(
    await allFinished(s.acceptFuts))

  # close and cleanup all connections
  await s.connManager.close()

  for t in s.transports:
    try:
        await t.stop()
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      warn "error cleaning up transports", msg = exc.msg

  trace "Switch stopped"

proc newSwitch*(peerInfo: PeerInfo,
                transports: seq[Transport],
                identity: Identify,
                muxers: Table[string, MuxerProvider],
                secureManagers: openarray[Secure] = [],
                maxConns = MaxConnections,
                maxPeerConns = MaxConnectionsPerPeer): Switch =
  if secureManagers.len == 0:
    raise (ref CatchableError)(msg: "Provide at least one secure manager")

  let switch = Switch(
    peerInfo: peerInfo,
    ms: newMultistream(),
    transports: transports,
    connManager: ConnManager.init(maxConns, maxPeerConns),
    identity: identity,
    muxers: muxers,
    secureManagers: @secureManagers)

  switch.mount(identity)
  return switch

proc isConnected*(s: Switch, peerInfo: PeerInfo): bool
  {.deprecated: "Use PeerID version".} =
  not isNil(peerInfo) and isConnected(s, peerInfo.peerId)

proc disconnect*(s: Switch, peerInfo: PeerInfo): Future[void]
  {.deprecated: "Use PeerID version", gcsafe.} =
  disconnect(s, peerInfo.peerId)

proc connect*(s: Switch, peerInfo: PeerInfo): Future[void]
  {.deprecated: "Use PeerID version".} =
  connect(s, peerInfo.peerId, peerInfo.addrs)

proc dial*(s: Switch,
           peerInfo: PeerInfo,
           proto: string):
           Future[Connection]
  {.deprecated: "Use PeerID version".} =
  dial(s, peerInfo.peerId, peerInfo.addrs, proto)
