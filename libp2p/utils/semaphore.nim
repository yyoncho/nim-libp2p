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

proc acquire*(s: AsyncSemaphore): Future[void] =
  ## Acquire a resource and decrement the resource
  ## counter. If no more resources are available,
  ## the returned future will not complete until
  ## the resource count goes above 0 again.
  ##

  var fut = newFuture[void]("AsyncSemaphore.acquire")
  fut.cancelCallback = proc(udata: pointer) =
    ## if future got canceled, increment the
    ## resource counter
    ##
    s.count.inc

  if s.count > 0:
    fut.complete()
  else:
    s.queue.addLast(fut)

  s.count.dec
  return fut

proc tryAcquire*(s: AsyncSemaphore): bool =
  ## Attempts to acquire a resource, if successful
  ## returns true, otherwise false
  ##

  # acquire() will return finished
  # futures if the resource count
  # is less than `size`
  return (s.acquire().finished)

proc release*(s: AsyncSemaphore) =
  ## Release a resource from the semaphore,
  ## by picking the first future from the queue
  ## and completing it and incrementing the
  ## internal resource count
  ##

  if s.count >= s.size:
    return

  while true:
    if s.queue.len > 0:
      var fut = s.queue.popFirst()
      # skip `canceled`, since the resource
      # count has been already adjusted in
      # the cancellation callback
      if fut.cancelled():
        continue

      if not fut.finished:
        fut.complete()

    s.count.inc # increment the result count
    return

when isMainModule:
  import unittest

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

    test "should tryAcquire":
      proc test() {.async.} =
        let sema = AsyncSemaphore.init(1)
        await sema.acquire()
        check sema.tryAcquire() == false

      waitFor(test())

    test "should tryAcquire and acquire":
      proc test() {.async.} =
        let sema = AsyncSemaphore.init(4)
        check sema.tryAcquire() == true
        check sema.tryAcquire() == true
        check sema.tryAcquire() == true
        check sema.tryAcquire() == true
        check sema.count == 0

        let fut = sema.acquire()
        check fut.finished == false
        check sema.count == -1
        # queue is only used when count is < 0
        check sema.queue.len == 1

        sema.release()
        check fut.finished == true

      waitFor(test())
