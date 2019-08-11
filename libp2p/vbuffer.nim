## Nim-Libp2p
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

## This module implements variable buffer.
import strutils
import varint, errors
export errors

type
  VBuffer* = object
    buffer*: seq[byte]
    offset*: int
    length*: int

template isEmpty*(vb: VBuffer): bool =
  ## Returns ``true`` if buffer ``vb`` is empty.
  len(vb.buffer) - vb.offset <= 0

template isEnough*(vb: VBuffer, length: int): bool =
  ## Returns ``true`` if buffer ``vb`` holds at least ``length`` bytes.
  len(vb.buffer) - vb.offset - length >= 0

proc len*(vb: VBuffer): int =
  ## Returns number of bytes left in buffer ``vb``.
  result = len(vb.buffer) - vb.offset

proc isLiteral[T](s: seq[T]): bool {.inline.} =
  type
    SeqHeader = object
      length, reserved: int
  (cast[ptr SeqHeader](s).reserved and (1 shl (sizeof(int) * 8 - 2))) != 0

# proc initVBuffer*(data: seq[byte], offset = 0): VBuffer =
#   ## Initialize VBuffer with shallow copy of ``data``.
#   if isLiteral(data):
#     result.buffer = data
#   else:
#     shallowCopy(result.buffer, data)
#   result.offset = offset

# proc initVBuffer*(data: openarray[byte], offset = 0): VBuffer =
#   ## Initialize VBuffer with copy of ``data``.
#   result.buffer = newSeq[byte](len(data))
#   if len(data) > 0:
#     copyMem(addr result.buffer[0], unsafeAddr data[0], len(data))
#   result.offset = offset

# proc initVBuffer*(): VBuffer =
#   ## Initialize empty VBuffer.
#   result.buffer = newSeqOfCap[byte](128)

proc init*(bt: typedesc[VBuffer], data: seq[byte], offset = 0): VBuffer =
  ## Initialize ``VBuffer`` with sequence ``data`` and initial offset
  ## ``offset``.
  ##
  ## If ``data`` is not literal, it will be stored as reference.
  if isLiteral(data):
    result.buffer = data
  else:
    shallowCopy(result.buffer, data)
  result.offset = offset

proc init*(bt: typedesc[VBuffer], data: openarray[byte], offset = 0): VBuffer =
  ## Initialize ``VBuffer`` with openarray ``data`` and initial offset
  ## ``offset``.
  ##
  ## ``data`` array will be copied to ``VBuffer`` instance.
  let length = len(data)
  if length > 0:
    result.buffer = newSeq[byte](length)
    copyMem(addr result.buffer[0], unsafeAddr data[0], length)
  else:
    result.buffer = newSeq[byte]()
  result.offset = offset

proc init*(bt: typedesc[VBuffer]): VBuffer =
  ## Initialize empty ``VBuffer``.
  result.buffer = newSeqOfCap[byte](128)
  result.offset = 0

# proc writeVarint*(vb: var VBuffer, value: LPSomeUVarint) =
#   ## Write ``value`` as variable unsigned integer.
#   var length = 0
#   # LibP2P varint supports only 63 bits.
#   var v = value and cast[type(value)](0x7FFF_FFFF_FFFF_FFFF)
#   vb.buffer.setLen(len(vb.buffer) + vsizeof(v))
#   let res = LP.putUVarint(toOpenArray(vb.buffer, vb.offset, len(vb.buffer) - 1),
#                           length, v)
#   doAssert(res == VarintStatus.Success)
#   vb.offset += length

proc writeVarint*(vb: var VBuffer,
                  value: LPSomeUVarint): Result[int, errors.Error] =
  ## Write ``value`` as variable unsigned integer. Procedure returns number of
  ## bytes written.
  var length = 0
  vb.buffer.setLen(len(vb.buffer) + vsizeof(value))
  let res = LP.putUVarint(toOpenArray(vb.buffer, vb.offset, len(vb.buffer) - 1),
                          value)
  if res.isOk:
    vb.offset += res.value
    result.ok(res.value)
  else:
    result.err(res.error)

# proc writeSeq*[T: byte|char](vb: var VBuffer, value: openarray[T]) =
#   ## Write array ``value`` to buffer ``vb``, value will be prefixed with
#   ## varint length of the array.
#   var length = 0
#   vb.buffer.setLen(len(vb.buffer) + vsizeof(len(value)) + len(value))
#   let res = LP.putUVarint(toOpenArray(vb.buffer, vb.offset, len(vb.buffer) - 1),
#                           length, uint(len(value)))
#   doAssert(res == VarintStatus.Success)
#   vb.offset += length
#   if len(value) > 0:
#     copyMem(addr vb.buffer[vb.offset], unsafeAddr value[0], len(value))
#     vb.offset += len(value)

proc writeSeq*[T: byte|char](vb: var VBuffer,
                             value: openarray[T]): Result[int, errors.Error] =
  ## Write array ``value`` to buffer ``vb``, value will be prefixed with
  ## varint length of the array. Procedure returns number of bytes written.
  var length = 0
  vb.buffer.setLen(len(vb.buffer) + vsizeof(len(value)) + len(value))
  let res = LP.putUVarint(toOpenArray(vb.buffer, vb.offset, len(vb.buffer) - 1),
                          uint64(len(value)))
  if res.isOk:
    length = res.value
    vb.offset += length
    if len(value) > 0:
      copyMem(addr vb.buffer[vb.offset], unsafeAddr value[0], len(value))
      length += len(value)
      vb.offset += len(value)
    result.ok(length)
  else:
    result.err(res.error)

# proc writeArray*[T: byte|char](vb: var VBuffer, value: openarray[T]) =
#   ## Write array ``value`` to buffer ``vb``, value will NOT be prefixed with
#   ## varint length of the array.
#   var length = 0
#   if len(value) > 0:
#     vb.buffer.setLen(len(vb.buffer) + len(value))
#     copyMem(addr vb.buffer[vb.offset], unsafeAddr value[0], len(value))
#     vb.offset += len(value)

proc writeArray*[T: byte|char](vb: var VBuffer,
                               value: openarray[T]): Result[int, errors.Error] =
  ## Write array ``value`` to buffer ``vb``, value will NOT be prefixed with
  ## varint length of the array. Procedure returns number of bytes written.
  var length = 0
  if len(value) > 0:
    vb.buffer.setLen(len(vb.buffer) + len(value))
    copyMem(addr vb.buffer[vb.offset], unsafeAddr value[0], len(value))
    vb.offset += len(value)
  result.ok(len(value))

proc finish*(vb: var VBuffer) =
  ## Finishes ``vb``.
  vb.offset = 0

proc peekVarint*(vb: var VBuffer,
                 value: var LPSomeUVarint): Result[int, errors.Error] =
  ## Peek unsigned integer from buffer ``vb`` and store result to ``value``.
  ##
  ## This procedure will not adjust internal offset.
  ##
  ## Returns number of bytes peeked from ``vb`` or ``-1`` on error.
  if vb.isEmpty():
    result.err(errors.EndOfBufferError)
  else:
    let res = LP.getUVarint(toOpenArray(vb.buffer, vb.offset,
                                        len(vb.buffer) - 1))
    if res.isOk:
      value = type(value)(res.value.value)
      result.ok(res.value.length)
    else:
      result.err(errors.VarintError)

proc peekSeq*[T: string|seq[byte]](vb: var VBuffer,
                                   value: var T): Result[int, errors.Error] =
  ## Peek length prefixed array from buffer ``vb`` and store result to
  ## ``value``.
  ##
  ## This procedure will not adjust internal offset.
  ##
  ## Returns number of bytes peeked from ``vb`` or ``-1`` on error.
  value.setLen(0)

  if vb.isEmpty():
    result.err(errors.EndOfBufferError)
  else:
    let res = LP.getUVarint(toOpenArray(vb.buffer, vb.offset,
                                        len(vb.buffer) - 1))
    if res.isErr():
      result.err(errors.VarintError)
    else:
      let size = res.value.value
      vb.offset += res.value.length
      if vb.isEnough(size):
        value.setLen(size)
        if size > 0'u64:
          copyMem(addr value[0], addr vb.buffer[vb.offset], size)
        result.ok(res.value.length + size)
      else:
        result.err(errors.EndOfBufferError)
      vb.offset -= res.value.length

proc peekArray*[T: char|byte](vb: var VBuffer,
                           value: var openarray[T]): Result[int, errors.Error] =
  ## Peek array from buffer ``vb`` and store result to ``value``.
  ##
  ## This procedure will not adjust internal offset.
  ##
  ## Returns number of bytes peeked from ``vb`` or ``-1`` on error.
  result = -1
  let length = len(value)
  if length > 0:
    if vb.isEnough(length):
      copyMem(addr value[0], addr vb.buffer[vb.offset], length)
      result.ok(length)
    else:
      result.err(errors.EndOfBufferError)
  else:
    result.ok(0)

proc readVarint*(vb: var VBuffer,
               value: var LPSomeUVarint): Result[int, errors.Error] {.inline.} =
  ## Read unsigned integer from buffer ``vb`` and store result to ``value``.
  ##
  ## Returns number of bytes consumed from ``vb`` or ``-1`` on error.
  let res = vb.peekVarint(value)
  if res.isOk:
    vb.offset += res.value
    result.ok(res.value)
  else:
    result.err(res.error)

proc readSeq*[T: string|seq[byte]](vb: var VBuffer,
                           value: var T): Result[int, errors.Error] {.inline.} =
  ## Read length prefixed array from buffer ``vb`` and store result to
  ## ``value``.
  ##
  ## Returns number of bytes consumed from ``vb`` or ``-1`` on error.
  let res = vb.peekSeq(value)
  if res.isOk:
    vb.offset += res.value
    result.ok(res.value)
  else:
    result.err(res.error)

proc readArray*[T: char|byte](vb: var VBuffer,
                              value: var openarray[T]): int {.inline.} =
  ## Read array from buffer ``vb`` and store result to ``value``.
  ##
  ## Returns number of bytes consumed from ``vb`` or ``-1`` on error.
  let res = vb.peekArray(value)
  if res.isOk:
    vb.offset += res.value
    result.ok(res.value)
  else:
    result.err(res.error)

proc `$`*(vb: VBuffer): string =
  ## Return hexadecimal string representation of buffer ``vb``.
  let length = (len(vb.buffer) - vb.offset) * 2
  result = newStringOfCap(length)
  for i in 0..<len(vb.buffer):
    result.add(toHex(vb.buffer[i]))
