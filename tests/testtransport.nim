{.used.}

import unittest, sequtils
import chronos, stew/byteutils
import ../libp2p/[stream/connection,
                  transports/transport,
                  transports/tcptransport,
                  multiaddress,
                  errors,
                  wire]

import ./helpers

suite "TCP transport":
  teardown:
    checkTrackers()

  test "test listener: handle write":
    proc testListener(): Future[bool] {.async, gcsafe.} =
      let ma: MultiAddress = Multiaddress.init("/ip4/0.0.0.0/tcp/0").tryGet()
      let transport: TcpTransport = TcpTransport.init()
      asyncCheck transport.start(ma)

      proc acceptHandler() {.async, gcsafe.} =
        let conn = await transport.accept()
        await conn.write("Hello!")
        await conn.close()

      let handlerWait = acceptHandler()

      let streamTransport = await connect(transport.ma)

      let msg = await streamTransport.read(6)

      await handlerWait.wait(5000.millis) # when no issues will not wait that long!
      await streamTransport.closeWait()
      await transport.stop()

      result = string.fromBytes(msg) == "Hello!"

    check:
      waitFor(testListener()) == true

  test "test listener: handle read":
    proc testListener(): Future[bool] {.async.} =
      let ma: MultiAddress = Multiaddress.init("/ip4/0.0.0.0/tcp/0").tryGet()

      let transport: TcpTransport = TcpTransport.init()
      asyncCheck transport.start(ma)

      proc acceptHandler() {.async, gcsafe.} =
        var msg = newSeq[byte](6)
        let conn = await transport.accept()
        await conn.readExactly(addr msg[0], 6)
        check string.fromBytes(msg) == "Hello!"
        await conn.close()

      let handlerWait = acceptHandler()
      let streamTransport: StreamTransport = await connect(transport.ma)
      let sent = await streamTransport.write("Hello!")

      await handlerWait.wait(5000.millis) # when no issues will not wait that long!
      await streamTransport.closeWait()
      await transport.stop()

      result = sent == 6

    check:
      waitFor(testListener()) == true

  test "test dialer: handle write":
    proc testDialer(address: TransportAddress): Future[bool] {.async.} =
      let handlerWait = newFuture[void]()
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async, gcsafe.} =
        var wstream = newAsyncStreamWriter(transp)
        await wstream.write("Hello!")
        await wstream.finish()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()
        handlerWait.complete()

      var server = createStreamServer(address, serveClient, {ReuseAddr})
      server.start()

      let ma: MultiAddress = MultiAddress.init(server.sock.getLocalAddress()).tryGet()
      let transport: TcpTransport = TcpTransport.init()
      let conn = await transport.dial(ma)
      var msg = newSeq[byte](6)
      await conn.readExactly(addr msg[0], 6)
      result = string.fromBytes(msg) == "Hello!"

      await handlerWait.wait(5000.millis) # when no issues will not wait that long!

      await conn.close()
      await transport.stop()

      server.stop()
      server.close()
      await server.join()

    check:
      waitFor(testDialer(initTAddress("0.0.0.0:0"))) == true

  test "test dialer: handle write":
    proc testDialer(address: TransportAddress): Future[bool] {.async, gcsafe.} =
      let handlerWait = newFuture[void]()
      proc serveClient(server: StreamServer,
                        transp: StreamTransport) {.async, gcsafe.} =
        var rstream = newAsyncStreamReader(transp)
        let msg = await rstream.read(6)
        check string.fromBytes(msg) == "Hello!"

        await rstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()
        handlerWait.complete()

      var server = createStreamServer(address, serveClient, {ReuseAddr})
      server.start()

      let ma: MultiAddress = MultiAddress.init(server.sock.getLocalAddress()).tryGet()
      let transport: TcpTransport = TcpTransport.init()
      let conn = await transport.dial(ma)
      await conn.write("Hello!")
      result = true

      await handlerWait.wait(5000.millis) # when no issues will not wait that long!

      await conn.close()
      await transport.stop()

      server.stop()
      server.close()
      await server.join()
    check:
      waitFor(testDialer(initTAddress("0.0.0.0:0"))) == true

  test "e2e: handle write":
    proc testListenerDialer(): Future[bool] {.async.} =
      let ma: MultiAddress = Multiaddress.init("/ip4/0.0.0.0/tcp/0").tryGet()

      let transport1: TcpTransport = TcpTransport.init()
      asyncCheck transport1.start(ma)

      proc acceptHandler() {.async, gcsafe.} =
        let conn = await transport1.accept()
        await conn.write("Hello!")
        await conn.close()

      let handlerWait = acceptHandler()

      let transport2: TcpTransport = TcpTransport.init()
      let conn = await transport2.dial(transport1.ma)
      var msg = newSeq[byte](6)
      await conn.readExactly(addr msg[0], 6)

      await handlerWait.wait(5000.millis) # when no issues will not wait that long!

      await conn.close()
      await transport2.stop()
      await transport1.stop()

      result = string.fromBytes(msg) == "Hello!"

    check:
      waitFor(testListenerDialer()) == true

  test "e2e: handle read":
    proc testListenerDialer(): Future[bool] {.async.} =
      let ma: MultiAddress = Multiaddress.init("/ip4/0.0.0.0/tcp/0").tryGet()

      let transport1: TcpTransport = TcpTransport.init()
      asyncCheck transport1.start(ma)

      proc acceptHandler() {.async, gcsafe.} =
        let conn = await transport1.accept()
        var msg = newSeq[byte](6)
        await conn.readExactly(addr msg[0], 6)
        check string.fromBytes(msg) == "Hello!"
        await conn.close()

      let handlerWait = acceptHandler()

      let transport2: TcpTransport = TcpTransport.init()
      let conn = await transport2.dial(transport1.ma)
      await conn.write("Hello!")

      await handlerWait.wait(5000.millis) # when no issues will not wait that long!

      await conn.close()
      await transport2.stop()
      await transport1.stop()
      result = true

    check:
      waitFor(testListenerDialer()) == true

  # test "e2e: should limit incoming connections":
  #   proc test() {.async.} =
  #     let ma: MultiAddress = Multiaddress.init("/ip4/0.0.0.0/tcp/0").tryGet()
  #     var times = 0
  #     proc connHandler(conn: Connection) {.async, gcsafe.} =
  #       times.inc()

  #     var transports: seq[TcpTransport]
  #     transports.add(TcpTransport.init(maxConns = 2))
  #     asyncCheck transports[0].listen(ma, connHandler)

  #     var conns: seq[Connection]
  #     try:
  #       for i in 0..10:
  #         let transport = TcpTransport.init()
  #         transports.add(transport)
  #         conns.add(await transport.dial(transports[0].ma).wait(10.millis))
  #         echo "DIALED"
  #     except AsyncTimeoutError:
  #       discard

  #     check times == 2
  #     await allFuturesThrowing(
  #       conns.mapIt(it.close()))

  #     await allFuturesThrowing(
  #       transports.mapIt(it.close()))

  #   waitFor(test())
