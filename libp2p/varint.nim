## Nim-Libp2p
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

## This module implements Variable Integer `VARINT`.
## This module supports two variants of variable integer
## - Google ProtoBuf varint, which is able to encode full uint64 number and
##   maximum size of encoded value is 10 octets (bytes).
## - LibP2P varint, which is able to encode only 63bits of uint64 number and
##   maximum size of encoded value is 9 octets (bytes).
import bitops
import errors
export errors

type
  PB* = object
    ## Use this type to specify Google ProtoBuf's varint encoding
  LP* = object
    ## Use this type to specify LibP2P varint encoding

  PBSomeUVarint* = uint | uint64 | uint32 | uint16 | uint8
  PBSomeSVarint* = int | int64 | int32 | int16 | int8
  PBSomeVarint* = PBSomeUVarint | PBSomeSVarint
  LPSomeUVarint* = uint | uint64 | uint32 | uint16 | uint8
  LPSomeVarint* = LPSomeUVarint
  SomeVarint* = PBSomeVarint | LPSomeVarint
  SomeUVarint* = PBSomeUVarint | LPSomeUVarint

  VarSint* = object
    value*: int64
    length*: int8

  VarUint* = object
    value*: uint64
    length*: int8

proc vsizeof*(x: SomeVarint): int {.inline.} =
  ## Returns number of bytes required to encode integer ``x`` as varint.
  if x == cast[type(x)](0):
    result = 1
  else:
    result = (fastLog2(x) + 1 + 7 - 1) div 7

template isOverflow*[T: SomeUnsignedInt](value: uint64): bool =
  # This helper allow to check for overflow when converting between unsigned
  # types.
  (cast[uint64](cast[T](value)) != value)

template isOverflow*[T: SomeSignedInt](value: int64): bool =
  # This helper allow to check for overflow when converting between signed
  # types.
  (cast[int64](cast[T](value)) != value)

proc getUVarint*[T: PB|LP](vt: typedesc[T],
                       pbytes: openarray[byte]): Result[VarUint, errors.Error] =
  when vt is PB:
    const MaxBits = 64'u8
  else:
    const MaxBits = 63'u8

  var status = errors.IncompleteError
  var shift = 0'u8
  var outlen = 0'i8
  var outval = 0'u64

  for i in 0..<len(pbytes):
    let b = pbytes[i]
    if shift >= MaxBits:
      status = errors.OverflowError
      break
    else:
      outval = outval or (cast[type(outval)](b and 0x7F'u8) shl shift)
      shift += 7
    inc(outlen)
    if (b and 0x80'u8) == 0'u8:
      status = errors.NoError
      break

  if status == errors.NoError:
    result.ok(VarUint(value: outval, length: outlen))
  else:
    result.err(status)

proc putUVarint*[T: PB|LP](vt: typedesc[T], pbytes: var openarray[byte],
                           value: SomeUVarint): Result[int, errors.Error] =
  ## Returns number of bytes used to encode value ``value``.
  var buffer: array[10, byte]
  var k = 0
  var v = value

  when vt is LP:
    if sizeof(value) == 8 and (value and 0x8000_0000_0000_0000'u64) != 0'u64:
      result.err(errors.OverflowError)
      return

  if v <= cast[type(value)](0x7F):
    buffer[0] = cast[byte](value and 0xFF)
    inc(k)
  else:
    while v != cast[type(value)](0):
      buffer[k] = cast[byte]((v and 0x7F) or 0x80)
      v = v shr 7
      inc(k)
    buffer[k - 1] = buffer[k - 1] and 0x7F'u8

  if len(pbytes) >= k:
    copyMem(addr pbytes[0], addr buffer[0], k)
    result.ok(k)
  else:
    result.err(errors.OverrunError)

proc getSVarint*(vt: typedesc[PB],
            pbytes: openarray[byte]): Result[VarSint, errors.Error] {.inline.} =
  let res = PB.getUVarint(pbytes)
  if res.isErr():
    result.err(res.error)
  else:
    var value = res.value.value
    if (value and 1'u64) != 0'u64:
      value = not(value shr 1)
    else:
      value = value shr 1
    result.ok(VarSint(value: cast[int64](value), length: res.value.length))

proc putSVarint*(vt: typedesc[PB], pbytes: var openarray[byte],
                 value: PBSomeSVarint): Result[int, errors.Error] {.inline.} =
  when sizeof(outval) == 8:
    var v: uint64 =
      if value < 0:
        not(cast[uint64](outval) shl 1)
      else:
        cast[uint64](outval) shl 1
  else:
    var v: uint32 =
      if outval < 0:
        not(cast[uint32](outval) shl 1)
      else:
        cast[uint32](outval) shl 1
  result = PB.putUVarint(pbytes, v)

proc encodeVarint*(vt: typedesc[PB],
              value: PBSomeVarint): Result[seq[byte], errors.Error] {.inline.} =
  when sizeof(value) == 1:
    var bytes = newSeq[byte](2)
  elif sizeof(value) == 2:
    var bytes = newSeq[byte](3)
  elif sizeof(value) == 4:
    var bytes = newSeq[byte](5)
  else:
    var bytes = newSeq[byte](10)

  when type(value) is PBSomeSVarint:
    let res = PB.putSVarint(bytes, value)
  else:
    let res = PB.putUVarint(bytes, value)

  if res.isOk:
    bytes.setLen(res.value.length)
    result.ok(bytes)
  else:
    result.err(res.error)

proc encodeVarint*(vt: typedesc[LP],
              value: LPSomeVarint): Result[seq[byte], errors.Error] {.inline.} =
  when sizeof(value) == 1:
    var bytes = newSeq[byte](2)
  elif sizeof(value) == 2:
    var bytes = newSeq[byte](3)
  elif sizeof(value) == 4:
    var bytes = newSeq[byte](5)
  else:
    var bytes = newSeq[byte](9)

  let res = LP.putUVarint(bytes, value)
  if res.isOk:
    bytes.setLen(res.value.length)
    result.ok(bytes)
  else:
    result.err(res.error)

proc decodeSVarint*(vt: typedesc[PB], it: type(SomeSignedInt),
                    data: openarray[byte]): auto {.inline.} =
  ## Decode ProtoBuffer's signed varint from array ``data`` and return it as
  ## result of type ``T``.
  result = Result[it, errors.Error](isOk: false)
  let res = PB.getSVarint(data)
  if res.isOk:
    if isOverflow[it](res.value.value):
      result.err(errors.OverflowError)
    else:
      result.ok(cast[it](res.value.value))
  else:
    result.err(res.error)

proc decodeUVarint*(vt: typedesc[PB|LP], it: type(SomeUnsignedInt),
                    data: openarray[byte]): auto {.inline.} =
  ## Decode unsigned varint from array ``data`` and return it as
  ## result of type ``it``.
  result = Result[it, errors.Error](isOk: false)
  let res = vt.getUVarint(data)
  if res.isOk:
    if isOverflow[it](res.value.value):
      result.err(errors.OverflowError)
    else:
      result.ok(cast[it](res.value.value))
  else:
    result.err(res.error)
