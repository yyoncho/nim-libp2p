## Nim-LibP2P
## Copyright (c) 2019 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

import tables, sequtils

import chronos,
       chronicles,
       metrics

import ../upgrademngrs/upgrade,
       ../muxers/muxer

type
  MuxedUpgrade* = ref object of Upgrade
    muxers*: Table[string, MuxerProvider]
    streamHandler*: StreamHandler

proc init*(
  T: type MuxedUpgrade,
  identity: Identify,
  muxers: Table[string, MuxerProvider],
  secureManagers: openarray[Secure] = [],
  ms: MultistreamSelect): T =

  var upgrader = T(
    identity: identity,
    muxers: muxers,
    secureManagers: secureManagers,
    ms: ms)

  upgrader.streamHandler = proc(conn: Connection) {.async, gcsafe.} = # noraises
    trace "Starting stream handler", conn
    try:
      await upgrader.ms.handle(conn) # handle incoming connection
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      trace "exception in stream handler", conn, msg = exc.msg
    finally:
      await conn.close()
    trace "Stream handler done", conn

  for key, val in muxers:
    val.streamHandler = upgrader.streamHandler
    val.muxerHandler = proc(muxer: Muxer): Future[void] =
      upgrader.muxerHandler(muxer)

  return upgrader

proc mux(u: MuxedUpgrade, conn: Connection): Future[Muxer] {.async, gcsafe.} =
  ## mux incoming connection

  trace "Muxing connection", conn
  if u.muxers.len == 0:
    warn "no muxers registered, skipping upgrade flow", conn
    return

  let muxerName = await u.ms.select(conn, toSeq(u.muxers.keys()))
  if muxerName.len == 0 or muxerName == "na":
    debug "no muxer available, early exit", conn
    return

  trace "Found a muxer", conn, muxerName

  # create new muxer for connection
  let muxer = u.muxers[muxerName].newMuxer(conn)

  # install stream handler
  muxer.streamHandler = u.streamHandler

  u.connManager.storeOutgoing(conn)
  u.connManager.storeMuxer(muxer)

  # start muxer read loop - the future will complete when loop ends
  let handlerFut = muxer.handle()

  # store it in muxed connections if we have a peer for it
  u.connManager.storeMuxer(muxer, handlerFut) # update muxer with handler

  return muxer

proc identify(u: MuxedUpgrade, muxer: Muxer) {.async, gcsafe.} =
  # new stream for identify
  var stream = await muxer.newStream()

  defer:
    if not(isNil(stream)):
      await stream.close() # close identify stream

  # do identify first, so that we have a
  # PeerInfo in case we didn't before
  await u.identify(stream)

proc muxerHandler(u: MuxedUpgrade, muxer: Muxer) {.async, gcsafe.} =
  let
    conn = muxer.connection

  if conn.peerInfo.isNil:
    warn "This version of nim-libp2p requires secure protocol to negotiate peerid"
    await muxer.close()
    return

  # store incoming connection
  u.connManager.storeIncoming(conn)

  # store muxer and muxed connection
  u.connManager.storeMuxer(muxer)

  try:
    await u.identify(muxer)
  except CatchableError as exc:
    # Identify is non-essential, though if it fails, it might indicate that
    # the connection was closed already - this will be picked up by the read
    # loop
    debug "Could not identify connection", conn, msg = exc.msg

  try:
    let peerId = conn.peerInfo.peerId

    proc peerCleanup() {.async.} =
      try:
        await muxer.connection.join()
        await u.connManager.triggerConnEvent(
          peerId, ConnEvent(kind: ConnEventKind.Disconnected))
        await u.connManager.triggerPeerEvents(peerId, PeerEvent.Left)
      except CatchableError as exc:
        # This is top-level procedure which will work as separate task, so it
        # do not need to propogate CancelledError and shouldn't leak others
        debug "Unexpected exception in switch muxer cleanup",
          conn, msg = exc.msg

    proc peerStartup() {.async.} =
      try:
        await u.connManager.triggerPeerEvents(peerId, PeerEvent.Joined)
        await u.connManager.triggerConnEvent(
          peerId, ConnEvent(kind: ConnEventKind.Connected, incoming: true))
      except CatchableError as exc:
        # This is top-level procedure which will work as separate task, so it
        # do not need to propagate CancelledError and shouldn't leak others
        debug "Unexpected exception in switch muxer startup",
          conn, msg = exc.msg

    # All the errors are handled inside `peerStartup()` procedure.
    asyncSpawn peerStartup()

    # All the errors are handled inside `peerCleanup()` procedure.
    asyncSpawn peerCleanup()

  except CancelledError as exc:
    await muxer.close()
    raise exc
  except CatchableError as exc:
    await muxer.close()
    libp2p_failed_upgrade.inc()
    trace "Exception in muxer handler", conn, msg = exc.msg

method upgradeOutgoing(s: Switch, conn: Connection): Future[Connection] {.async, gcsafe.} =
  try:
    trace "Upgrading outgoing connection", conn

    let sconn = await s.secure(conn) # secure the connection
    if isNil(sconn):
      raise newException(UpgradeFailedError,
        "unable to secure connection, stopping upgrade")

    if sconn.peerInfo.isNil:
      raise newException(UpgradeFailedError,
        "current version of nim-libp2p requires that secure protocol negotiates peerid")

    let muxer = await s.mux(sconn) # mux it if possible
    if muxer == nil:
      # TODO this might be relaxed in the future
      raise newException(UpgradeFailedError,
        "a muxer is required for outgoing connections")

    try:
      await s.identify(muxer)
    except CatchableError as exc:
      # Identify is non-essential, though if it fails, it might indicate that
      # the connection was closed already - this will be picked up by the read
      # loop
      debug "Could not identify connection", conn, msg = exc.msg

    if isNil(sconn.peerInfo):
      await sconn.close()
      raise newException(UpgradeFailedError,
        "No peerInfo for connection, stopping upgrade")

    s.connManager.updateConn(conn, sconn)
    trace "Upgraded outgoing connection", conn, sconn

    return sconn
  except CatchableError as exc:
    if not isNil(conn):
      await conn.close()

method upgradeIncoming(s: Switch, incomingConn: Connection) {.async, gcsafe.} = # noraises
  trace "Upgrading incoming connection", incomingConn
  let ms = newMultistream()

  # secure incoming connections
  proc securedHandler (conn: Connection,
                       proto: string)
                       {.async, gcsafe, closure.} =
    trace "Starting secure handler", conn
    let secure = s.secureManagers.filterIt(it.codec == proto)[0]

    try:
      var sconn = await secure.secure(conn, false)
      if isNil(sconn):
        return

      defer:
        await sconn.close()

      s.connManager.updateConn(conn, sconn)

      # add the muxer
      for muxer in s.muxers.values:
        ms.addHandler(muxer.codecs, muxer)

      # handle subsequent secure requests
      await ms.handle(sconn)

    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      debug "Exception in secure handler", msg = exc.msg, conn

    trace "Stopped secure handler", conn

  try:
    if (await ms.select(incomingConn)): # just handshake
      # add the secure handlers
      for k in s.secureManagers:
        ms.addHandler(k.codec, securedHandler)

    # handle un-secured connections
    # we handshaked above, set this ms handler as active
    await ms.handle(incomingConn, active = true)
  except CatchableError as exc:
    debug "exception upgrading incoming", exc = exc.msg
  finally:
    await incomingConn.close()
