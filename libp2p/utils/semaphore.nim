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

# TODO: this should probably go in chronos

type
  AsyncSemaphore* = ref object of RootObj
    size*: int
    count*: int
    queue*: Deque[Future[void]]

proc init*(T: type AsyncSemaphore, size: int): T =
  T(size: size, count: size)

proc tryAcquire*(s: AsyncSemaphore): bool =
  ## Attempts to acquire a resource, if successful
  ## the returns true, if not, returns false
  ##

  if s.count > 0:
    s.count.dec
    return true

  return false

proc acquire*(s: AsyncSemaphore): Future[void] =
  ## Acquire a resource and decrement the semaphore's
  ## counter. If no more resources are available,
  ## the returned future will not complete until
  ## the resource count goes above 0 again.
  ##

  var fut = newFuture[void]("AsyncSemaphore.acquire")
  if s.count > 0:
    fut.complete()
  else:
    s.queue.addLast(fut)

  s.count.dec
  return fut

proc release*(s: AsyncSemaphore) =
  ## Release a resource from the semaphore,
  ## by picking the first future from the queue
  ## and completing it and incrementing the
  ## internal resource count
  ##

  if s.count >= s.size:
    return

  while true:
    s.count.inc
    if s.queue.len == 0:
      return

    var fut = s.queue.popFirst()
    if not(fut.cancelled() or fut.finished()):
      fut.complete()
      return

when isMainModule:
  import unittest
  import chronos

  suite "AsyncSemaphore":
    test "should acquire":
      proc test() {.async.} =
        let sema = AsyncSemaphore.init(3)

        await sema.acquire()
        await sema.acquire()
        await sema.acquire()

        check sema.count == 0

      waitFor(test())

    test "should release":
      proc test() {.async.} =
        let sema = AsyncSemaphore.init(3)

        await sema.acquire()
        await sema.acquire()
        await sema.acquire()

        check sema.count == 0
        sema.release()
        sema.release()
        sema.release()
        check sema.count == 3

      waitFor(test())

    test "should queue acquire":
      proc test() {.async.} =
        let sema = AsyncSemaphore.init(1)

        await sema.acquire()
        let fut = sema.acquire()

        check sema.count == -1
        check sema.queue.len == 1
        sema.release()
        sema.release()
        check sema.count == 1

        check fut.finished()

      waitFor(test())

    test "should handle canceled":
      proc test() {.async.} =
        let sema = AsyncSemaphore.init(1)

        await sema.acquire()
        let fut = sema.acquire()

        check sema.count == -1
        check sema.queue.len == 1
        fut.cancel()
        sema.release()
        check sema.count == 1

        check fut.cancelled()

      waitFor(test())

    test "should keep count == size":
      proc test() {.async.} =
        let sema = AsyncSemaphore.init(1)
        sema.release()
        sema.release()
        sema.release()
        check sema.count == 1

      waitFor(test())

    test "should try acquire":
      proc test() {.async.} =
        let sema = AsyncSemaphore.init(1)
        await sema.acquire()
        check sema.tryAcquire() == false

      waitFor(test())
