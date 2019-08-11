## Nim-Libp2p
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

## This module implements minimal Google's ProtoBuf primitives.
import ../varint, ../errors
export errors

const
  MaxMessageSize* = 1'u shl 22

type
  ProtoFieldKind* = enum
    ## Protobuf's field types enum
    Varint, Fixed64, Length, StartGroup, EndGroup, Fixed32

  ProtoFlags* = enum
    ## Protobuf's encoding types
    WithVarintLength

  ProtoBuffer* = object
    ## Protobuf's message representation object
    options: set[ProtoFlags]
    buffer*: seq[byte]
    offset*: int
    length*: int

  ProtoField* = object
    ## Protobuf's message field representation object
    index: int
    case kind: ProtoFieldKind
    of Varint:
      vint*: uint64
    of Fixed64:
      vfloat64*: float64
    of Length:
      vbuffer*: seq[byte]
    of Fixed32:
      vfloat32*: float32
    of StartGroup, EndGroup:
      discard

template protoHeader*(index: int, wire: ProtoFieldKind): uint =
  ## Get protobuf's field header integer for ``index`` and ``wire``.
  ((uint(index) shl 3) or cast[uint](wire))

template protoHeader*(field: ProtoField): uint =
  ## Get protobuf's field header integer for ``field``.
  ((uint(field.index) shl 3) or cast[uint](field.kind))

template toOpenArray*(pb: ProtoBuffer): untyped =
  toOpenArray(pb.buffer, pb.offset, len(pb.buffer) - 1)

template isEmpty*(pb: ProtoBuffer): bool =
  len(pb.buffer) - pb.offset <= 0

template isEnough*(pb: ProtoBuffer, length: int): bool =
  len(pb.buffer) - pb.offset - length >= 0

template getPtr*(pb: ProtoBuffer): pointer =
  cast[pointer](unsafeAddr pb.buffer[pb.offset])

template getLen*(pb: ProtoBuffer): int =
  len(pb.buffer) - pb.offset

proc vsizeof*(field: ProtoField): int {.inline.} =
  ## Returns number of bytes required to store protobuf's field ``field``.
  result = vsizeof(protoHeader(field))
  case field.kind
  of ProtoFieldKind.Varint:
    result += vsizeof(field.vint)
  of ProtoFieldKind.Fixed64:
    result += sizeof(field.vfloat64)
  of ProtoFieldKind.Fixed32:
    result += sizeof(field.vfloat32)
  of ProtoFieldKind.Length:
    result += vsizeof(uint(len(field.vbuffer))) + len(field.vbuffer)
  else:
    discard

proc init*(t: typedesc[ProtoField], index: int, value: SomeVarint): ProtoField =
  ## Initialize ProtoField with integer value.
  result = ProtoField(kind: Varint, index: index)
  when type(value) is uint64:
    result.vint = value
  else:
    result.vint = cast[uint64](value)

proc init*(t: typedesc[ProtoField], index: int,
           value: openarray[byte]): ProtoField =
  ## Initialize ProtoField with bytes array.
  result = ProtoField(kind: Length, index: index)
  if len(value) > 0:
    result.vbuffer = newSeq[byte](len(value))
    copyMem(addr result.vbuffer[0], unsafeAddr value[0], len(value))

proc init*(t: typedesc[ProtoField], index: int, value: string): ProtoField =
  ## Initialize ProtoField with string.
  result = ProtoField(kind: Length, index: index)
  if len(value) > 0:
    result.vbuffer = newSeq[byte](len(value))
    copyMem(addr result.vbuffer[0], unsafeAddr value[0], len(value))

proc init*(t: typedesc[ProtoField], index: int,
           value: ProtoBuffer): ProtoField {.inline.} =
  ## Initialize ProtoField with nested message stored in ``value``.
  ##
  ## Note: This procedure performs shallow copy of ``value`` sequence.
  result = ProtoField(kind: Length, index: index)
  if len(value.buffer) > 0:
    shallowCopy(result.vbuffer, value.buffer)

proc init*(t: typedesc[ProtoBuffer], data: seq[byte], offset = 0,
           options: set[ProtoFlags] = {}): ProtoBuffer =
  ## Initialize ProtoBuffer with shallow copy of ``data``.
  shallowCopy(result.buffer, data)
  result.offset = offset
  result.options = options

proc init*(t: typedesc[ProtoBuffer],
           options: set[ProtoFlags] = {}): ProtoBuffer =
  ## Initialize ProtoBuffer with new sequence of capacity ``cap``.
  result.buffer = newSeqOfCap[byte](128)
  result.options = options
  if WithVarintLength in options:
    # Our buffer will start from position 10, so we can store length of buffer
    # in [0, 9].
    result.buffer.setLen(10)
    result.offset = 10

proc write*(pb: var ProtoBuffer, field: ProtoField) =
  ## Encode protobuf's field ``field`` and store it to protobuf's buffer ``pb``.
  pb.buffer.setLen(len(pb.buffer) + vsizeof(field))
  var length = PB.putUVarint(pb.toOpenArray(), protoHeader(field))
  # We do not care about error here, because ProtoBuffer's version of varint
  # properly supports `uint64` and we control output buffer.
  pb.offset += length.value
  case field.kind
  of ProtoFieldKind.Varint:
    length = PB.putUVarint(pb.toOpenArray(), field.vint)
    pb.offset += length.value
  of ProtoFieldKind.Fixed64:
    var value = cast[uint64](field.vfloat64)
    pb.buffer[pb.offset] = byte(value and 0xFF'u32)
    pb.buffer[pb.offset + 1] = byte((value shr 8) and 0xFF'u32)
    pb.buffer[pb.offset + 2] = byte((value shr 16) and 0xFF'u32)
    pb.buffer[pb.offset + 3] = byte((value shr 24) and 0xFF'u32)
    pb.buffer[pb.offset + 4] = byte((value shr 32) and 0xFF'u32)
    pb.buffer[pb.offset + 5] = byte((value shr 40) and 0xFF'u32)
    pb.buffer[pb.offset + 6] = byte((value shr 48) and 0xFF'u32)
    pb.buffer[pb.offset + 7] = byte((value shr 56) and 0xFF'u32)
    pb.offset += 8
  of ProtoFieldKind.Fixed32:
    var value = cast[uint32](field.vfloat32)
    pb.buffer[pb.offset] = byte(value and 0xFF'u32)
    pb.buffer[pb.offset + 1] = byte((value shr 8) and 0xFF'u32)
    pb.buffer[pb.offset + 2] = byte((value shr 16) and 0xFF'u32)
    pb.buffer[pb.offset + 3] = byte((value shr 24) and 0xFF'u32)
    pb.offset += 4
  of ProtoFieldKind.Length:
    length = PB.putUVarint(pb.toOpenArray(), uint(len(field.vbuffer)))
    pb.offset += length.value
    if len(field.vbuffer) > 0:
      copyMem(addr pb.buffer[pb.offset], unsafeAddr field.vbuffer[0],
              len(field.vbuffer))
      pb.offset += len(field.vbuffer)
  else:
    discard

proc finish*(pb: var ProtoBuffer) =
  ## Prepare protobuf's buffer ``pb`` for writing to stream.
  if WithVarintLength in pb.options:
    let size = uint(len(pb.buffer) - 10)
    let pos = 10 - vsizeof(size)
    let res = PB.putUVarint(pb.buffer.toOpenArray(pos, 9), size)
    # We do not care about error here, because ProtoBuffer's version of varint
    # properly supports `uint64` and we control output buffer.
    pb.offset = pos
  else:
    pb.offset = 0

proc getVarintValue*(data: var ProtoBuffer, it: type[SomeInteger],
                     field: int): auto =
  ## Get value of `Varint` type.
  result = Result[it, errors.Error](isOk: false)
  var soffset = data.offset

  if data.isEmpty():
    result.err(errors.IncompleteError)
    return

  let header = PB.getUVarint(data.toOpenArray())
  if header.isErr:
    data.offset = soffset
    result.err(errors.VarintError)
    return

  data.offset += header.value.length
  if header.value.value != protoHeader(field, Varint):
    data.offset = soffset
    result.err(errors.ProtobufIncorrectFieldError)
    return

  if data.isEmpty():
    data.offset = soffset
    result.err(errors.IncompleteError)
    return

  when T is SomeSignedInt:
    let res = PB.getSVarint(data.toOpenArray())
  else:
    let res = PB.getUVarint(data.toOpenArray())

  if res.isErr:
    data.offset = soffset
    result.err(errors.VarintError)
    return

  if isOverflow[it](res.value.value):
    data.offset = soffset
    result.err(errors.OverflowError)
  else:
    data.offset += res.value.length
    result.ok(cast[it](res.value.value))

proc getLengthValue*(data: var ProtoBuffer, sst: type[seq[byte]|string],
                     field: int): auto =
  ## Get value of `Length` type.
  result = Result[sst, errors.Error](isOk: false)
  var soffset = data.offset

  when sst is seq[byte]:
    var buffer = newSeq[byte](0)
  else:
    var buffer = newString(0)

  if data.isEmpty():
    result.err(errors.IncompleteError)
    return

  let header = PB.getUVarint(data.toOpenArray())
  if header.isErr:
    data.offset = soffset
    result.err(errors.VarintError)
    return

  data.offset += header.value.length
  if header.value.value != protoHeader(field, Length):
    data.offset = soffset
    result.err(errors.ProtobufIncorrectFieldError)
    return

  if data.isEmpty():
    data.offset = soffset
    result.err(errors.IncompleteError)
    return

  let res = PB.getUVarint(data.toOpenArray())
  if res.isErr:
    data.offset = soffset
    result.err(errors.VarintError)
    return

  data.offset += res.value.length
  if res.value.value > uint64(MaxMessageSize):
    data.offset = soffset
    result.err(errors.ProtobufFieldSizeTooLargeError)
    return

  if not(data.isEnough(int(res.value.value))):
    data.offset = soffset
    result.err(errors.IncompleteError)
    return

  buffer.setLen(res.value.value)
  if res.value.value > 0'u64:
    copyMem(addr buffer[0], addr data.buffer[data.offset], res.value.value)
  data.offset += int(res.value.value)
  result.ok(buffer)

proc getBytes*(data: var ProtoBuffer,
               field: int): Result[seq[byte], errors.Error] {.inline.} =
  ## Get value of `Length` type as bytes.
  result = getLengthValue(data, seq[byte], field)

proc getString*(data: var ProtoBuffer,
                field: int): Result[string, errors.Error] {.inline.} =
  ## Get value of `Length` type as string.
  result = getLengthValue(data, string, field)

proc enterSubmessage*(data: var ProtoBuffer): Result[int, errors.Error] =
  ## Processes protobuf's sub-message and adjust internal offset to enter
  ## inside of sub-message. Returns field index of sub-message field.
  var soffset = data.offset

  if data.isEmpty():
    result.err(errors.IncompleteError)
    return

  var header = PB.getUVarint(data.toOpenArray())
  if header.isErr:
    result.err(errors.VarintError)
    return

  data.offset += header.value.length
  if (header.value.value and 0x07'u64) != cast[uint64](ProtoFieldKind.Length):
    data.offset = soffset
    result.err(errors.ProtobufIncorrectFieldError)
    return

  if data.isEmpty():
    data.offset = soffset
    result.err(errors.IncompleteError)
    return

  let res = PB.getUVarint(data.toOpenArray())
  if res.isErr:
    result.err(errors.VarintError)
    return

  if res.value.value > uint64(MaxMessageSize):
    data.offset = soffset
    result.err(errors.ProtobufFieldSizeTooLargeError)
    return

  if not(data.isEnough(int(res.value.value))):
    data.offset = soffset
    result.err(errors.IncompleteError)
    return

  data.offset += int(res.value.length)
  data.length = int(res.value.value)
  result.ok(int(header.value.value shr 3))

proc skipSubmessage*(pb: var ProtoBuffer): Result[int, errors.Error] =
  ## Skip current protobuf's sub-message and adjust internal offset to the
  ## end of sub-message.
  if pb.length == 0:
    result.err(errors.IncorrectError)
    return
  pb.offset += pb.length
  result.ok(pb.length)
  pb.length = 0
