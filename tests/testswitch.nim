import unittest, tables
import chronos
import ../libp2p/[switch,
                  multistream,
                  protocols/identify,
                  connection,
                  transports/transport,
                  transports/tcptransport,
                  multiaddress,
                  peerinfo,
                  crypto/crypto,
                  peer,
                  protocols/protocol,
                  muxers/muxer,
                  muxers/mplex/mplex,
                  muxers/mplex/types,
                  protocols/secure/secio,
                  protocols/secure/secure]

when defined(nimHasUsed): {.used.}

const TestCodec = "/test/proto/1.0.0"

type
  TestProto = ref object of LPProtocol

method init(p: TestProto) {.gcsafe.} =
  proc handle(conn: Connection, proto: string) {.async, gcsafe.} =
    let msg = cast[string](await conn.readLp())
    check "Hello!" == msg
    await conn.writeLp("Hello!")
    await conn.close()

  p.codec = TestCodec
  p.handler = handle

proc createSwitch(ma: MultiAddress): (Switch, PeerInfo) =
  var peerInfo: PeerInfo = PeerInfo.init(PrivateKey.random(RSA))
  peerInfo.addrs.add(ma)
  let identify = newIdentify(peerInfo)

  proc createMplex(conn: Connection): Muxer =
    result = newMplex(conn)

  let mplexProvider = newMuxerProvider(createMplex, MplexCodec)
  let transports = @[Transport(newTransport(TcpTransport))]
  let muxers = [(MplexCodec, mplexProvider)].toTable()
  let secureManagers = [(SecioCodec, Secure(newSecio(peerInfo.privateKey)))].toTable()
  let switch = newSwitch(peerInfo,
                         transports,
                         identify,
                         muxers,
                         secureManagers)
  result = (switch, peerInfo)

suite "Switch":
  test "e2e use switch dial proto string":
    proc testSwitch(): Future[bool] {.async, gcsafe.} =
      let ma1: MultiAddress = Multiaddress.init("/ip4/0.0.0.0/tcp/0")
      let ma2: MultiAddress = Multiaddress.init("/ip4/0.0.0.0/tcp/0")

      var peerInfo1, peerInfo2: PeerInfo
      var switch1, switch2: Switch
      var awaiters: seq[Future[void]]

      (switch1, peerInfo1) = createSwitch(ma1)

      let testProto = new TestProto
      testProto.init()
      testProto.codec = TestCodec
      switch1.mount(testProto)
      (switch2, peerInfo2) = createSwitch(ma2)
      awaiters.add(await switch1.start())
      awaiters.add(await switch2.start())
      let conn = await switch2.dial(switch1.peerInfo, TestCodec)
      await conn.writeLp("Hello!")
      let msg = cast[string](await conn.readLp())
      check "Hello!" == msg

      await allFutures(switch1.stop(), switch2.stop())
      await allFutures(awaiters)
      result = true

    check:
      waitFor(testSwitch()) == true

  test "e2e use switch no proto string":
    proc testSwitch(): Future[bool] {.async, gcsafe.} =
      let ma1: MultiAddress = Multiaddress.init("/ip4/0.0.0.0/tcp/0")
      let ma2: MultiAddress = Multiaddress.init("/ip4/0.0.0.0/tcp/0")

      var peerInfo1, peerInfo2: PeerInfo
      var switch1, switch2: Switch
      (switch1, peerInfo1) = createSwitch(ma1)
      var awaiters: seq[Future[void]]
      awaiters.add(await switch1.start())

      (switch2, peerInfo2) = createSwitch(ma2)
      awaiters.add(await switch2.start())
      var conn = await switch2.dial(switch1.peerInfo)

      check isNil(conn)
      discard allFutures(switch1.stop(), switch2.stop())
      await allFutures(awaiters)
      result = true

    check:
      waitFor(testSwitch()) == true

  test "e2e use switch nested dial":
    proc testSwitch(): Future[bool] {.async, gcsafe.} =
      let ma1: MultiAddress = Multiaddress.init("/ip4/0.0.0.0/tcp/0")
      let ma2: MultiAddress = Multiaddress.init("/ip4/0.0.0.0/tcp/0")

      var peerInfo1, peerInfo2: PeerInfo
      var switch1, switch2: Switch
      (switch1, peerInfo1) = createSwitch(ma1)
      var awaiters: seq[Future[void]]
      awaiters.add(await switch1.start())

      (switch2, peerInfo2) = createSwitch(ma2)
      awaiters.add(await switch2.start())

      var proto1 = new LPProtocol
      proto1.codec = "/proto/1"
      var awaiter = newFuture[void]()
      proc handler1(conn: Connection, proto: string) {.async, gcsafe.} =
        var nested = await switch1.dial(switch2.peerInfo, "/proto/2")
        await nested.writeLp("proto 1")
        check cast[string](await nested.readLp()) == "proto 2"
        await nested.close()
        awaiter.complete()

      proto1.handler = handler1
      switch1.mount(proto1)

      var proto2 = new LPProtocol
      proto2.codec = "/proto/2"
      proc handler2(conn: Connection, proto: string) {.async, gcsafe.} =
        check cast[string](await conn.readLp()) == "proto 1"
        await conn.writeLp("proto 2")
        await conn.close()

      proto2.handler = handler2
      switch2.mount(proto2)

      discard await switch1.dial(switch1.peerInfo, "/proto/1")
      await awaiter
      discard allFutures(switch1.stop(), switch2.stop())
      await allFutures(awaiters)
      result = true

    check:
      waitFor(testSwitch()) == true
