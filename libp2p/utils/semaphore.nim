## Nim-Libp2p
## Copyright (c) 2020 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

import deques
import chronos

type
  AsyncSemaphore* = ref object of RootObj
    count: int
    queue: Deque[Future[void]]

proc init*(T: type AsyncSemaphore, count: int): T =
  T(count: count)

proc acquire*(s: AsyncSemaphore): Future[void] =
  ## Acquire a resource and decrement the semaphore's
  ## counter. If no more resources are available,
  ## the returned future will not complete until
  ## the resource count goes above 0 again.
  ##

  var fut = newFuture[void]("AsyncSemaphore.acquire")
  if s.count > 0:
    s.count.dec
    fut.complete()
    return fut

  s.queue.addLast(fut)
  return fut

proc tryAcquire*(s: AsyncSemaphore): bool =
  ## Attempts to acquire a resource, if successful
  ## the returns true, if not, returns false
  ##

  if s.count > 0:
    s.count.dec
    return true

  return false

proc release*(s: AsyncSemaphore) =
  ## Release a resource from the semaphore,
  ## by picking the first future from the queue
  ## and completing it and incrementing the
  ## internal resource count
  ##

  while s.queue.len > 0:
    doAssert(s.count == 0,
      "the semaphore state is invalid!")

    var fut = s.queue.popFirst()
    if not fut.cancelled():
      fut.complete()
      s.count.inc
      return

when isMainModule:
  import unittest

  suite "AsyncSemaphore":
    test "should acquire":
      proc test() {.async.} =
        let sema = AsyncSemaphore.init(10)

        var count = 0
        proc use() {.async.} =
          while true:
            await sema.acquire()
            count.inc()

        asyncSpawn use()
        await sleepAsync(10.millis)
        check count == 10

      waitFor(test())

    test "should release":
      proc test() {.async.} =
        let sema = AsyncSemaphore.init(1)

        var completed: bool
        proc timeIt() {.async.} =
          await sleepAsync(200.millis)
          check false

        proc release() {.async.} =
          await sleepAsync(10.millis)
          sema.release()

        asyncSpawn timeIt()
        await sema.acquire()
        asyncSpawn release()
        await sema.acquire()
        check true

      waitFor(test())

    test "should try acquire":
      proc test() {.async.} =
        let sema = AsyncSemaphore.init(1)
        await sema.acquire()
        check sema.tryAcquire() == false

      waitFor(test())
