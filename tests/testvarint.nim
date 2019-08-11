import unittest
import ../libp2p/[varint, errors]

const PBedgeValues = [
  0'u64, (1'u64 shl 7) - 1'u64,
  (1'u64 shl 7), (1'u64 shl 14) - 1'u64,
  (1'u64 shl 14), (1'u64 shl 21) - 1'u64,
  (1'u64 shl 21), (1'u64 shl 28) - 1'u64,
  (1'u64 shl 28), (1'u64 shl 35) - 1'u64,
  (1'u64 shl 35), (1'u64 shl 42) - 1'u64,
  (1'u64 shl 42), (1'u64 shl 49) - 1'u64,
  (1'u64 shl 49), (1'u64 shl 56) - 1'u64,
  (1'u64 shl 56), (1'u64 shl 63) - 1'u64,
  (1'u64 shl 63), 0xFFFF_FFFF_FFFF_FFFF'u64
]

const PBedgeExpects = [
  "00", "7F",
  "8001", "FF7F",
  "808001", "FFFF7F",
  "80808001", "FFFFFF7F",
  "8080808001", "FFFFFFFF7F",
  "808080808001", "FFFFFFFFFF7F",
  "80808080808001", "FFFFFFFFFFFF7F",
  "8080808080808001", "FFFFFFFFFFFFFF7F",
  "808080808080808001", "FFFFFFFFFFFFFFFF7F",
  "80808080808080808001", "FFFFFFFFFFFFFFFFFF01"
]

const PBedgeSizes = [
  1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10
]

const LPedgeValues = [
  0'u64, (1'u64 shl 7) - 1'u64,
  (1'u64 shl 7), (1'u64 shl 14) - 1'u64,
  (1'u64 shl 14), (1'u64 shl 21) - 1'u64,
  (1'u64 shl 21), (1'u64 shl 28) - 1'u64,
  (1'u64 shl 28), (1'u64 shl 35) - 1'u64,
  (1'u64 shl 35), (1'u64 shl 42) - 1'u64,
  (1'u64 shl 42), (1'u64 shl 49) - 1'u64,
  (1'u64 shl 49), (1'u64 shl 56) - 1'u64,
  (1'u64 shl 56), (1'u64 shl 63) - 1'u64,
]

const LPedgeSizes = [
  1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9
]

const LPedgeExpects = [
  "00", "7F",
  "8001", "FF7F",
  "808001", "FFFF7F",
  "80808001", "FFFFFF7F",
  "8080808001", "FFFFFFFF7F",
  "808080808001", "FFFFFFFFFF7F",
  "80808080808001", "FFFFFFFFFFFF7F",
  "8080808080808001", "FFFFFFFFFFFFFF7F",
  "808080808080808001", "FFFFFFFFFFFFFFFF7F",
]

proc hexChar*(c: byte, lowercase: bool = false): string =
  var alpha: int
  if lowercase:
    alpha = ord('a')
  else:
    alpha = ord('A')
  result = newString(2)
  let t1 = ord(c) shr 4
  let t0 = ord(c) and 0x0F
  case t1
  of 0..9: result[0] = chr(t1 + ord('0'))
  else: result[0] = chr(t1 - 10 + alpha)
  case t0:
  of 0..9: result[1] = chr(t0 + ord('0'))
  else: result[1] = chr(t0 - 10 + alpha)

proc toHex*(a: openarray[byte], lowercase: bool = false): string =
  result = ""
  for i in a:
    result = result & hexChar(i, lowercase)

suite "Variable integer test suite":

  test "vsizeof() edge cases test":
    for i in 0..<len(PBedgeValues):
      check vsizeof(PBedgeValues[i]) == PBedgeSizes[i]

  test "isOverflow() edge cases test":
    check:
      isOverflow[int8](-129'i64) == true
      isOverflow[int8](128'i64) == true
      isOverflow[int16](-32769'i64) == true
      isOverflow[int16](32768'i64) == true
      isOverflow[int32](-2147483649'i64) == true
      isOverflow[int32](2147483648'i64) == true
      isOverflow[uint8](256'u64) == true
      isOverflow[uint16](65536'u64) == true
      isOverflow[uint32](4294967296'u64) == true

  test "[ProtoBuf] Success edge cases test":
    var buffer = newSeq[byte]()
    var length = 0
    var value = 0'u64
    for i in 0..<len(PBedgeValues):
      buffer.setLen(PBedgeSizes[i])

      zeroMem(addr buffer[0], len(buffer))
      value = 0'u64

      check PB.putUVarint(buffer, PBedgeValues[i]).isOk == true
      let res = PB.getUVarint(buffer)
      check:
        res.isOk == true
        res.value.value == PBedgeValues[i]
        toHex(buffer) == PBedgeExpects[i]

  test "[ProtoBuf] Buffer Overrun edge cases test":
    var buffer = newSeq[byte]()
    var length = 0
    for i in 0..<len(PBedgeValues):
      buffer.setLen(PBedgeSizes[i] - 1)

      if len(buffer) > 0:
        zeroMem(addr buffer[0], len(buffer))
      let res2 = PB.putUVarint(buffer, PBedgeValues[i])
      check:
        res2.isErr == true
        res2.error == errors.OverrunError

  test "[ProtoBuf] Buffer Incomplete edge cases test":
    var buffer = newSeq[byte]()
    var length = 0
    var value = 0'u64
    for i in 0..<len(PBedgeValues):
      buffer.setLen(PBedgeSizes[i])
      zeroMem(addr buffer[0], len(buffer))

      check:
        PB.putUVarint(buffer, PBedgeValues[i]).isOk == true
      buffer.setLen(len(buffer) - 1)
      let res = PB.getUVarint(buffer)
      check:
        res.isErr == true
        res.error == errors.IncompleteError

  test "[ProtoBuf] Integer Overflow 32bit test":
    var buffer = newSeq[byte]()
    var length = 0
    for i in 0..<len(PBedgeValues):
      if PBedgeSizes[i] > 5:
        var value = 0'u32
        buffer.setLen(PBedgeSizes[i])
        check PB.putUVarint(buffer, PBedgeValues[i]).isOk == true
        let res = PB.decodeUVarint(uint32, buffer)
        check:
          res.isErr == true
          res.error == errors.OverflowError

  test "[ProtoBuf] Integer Overflow 64bit test":
    var buffer = newSeq[byte]()
    var length = 0
    for i in 0..<len(PBedgeValues):
      if PBedgeSizes[i] > 9:
        var value = 0'u64
        buffer.setLen(PBedgeSizes[i] + 1)
        zeroMem(addr buffer[0], len(buffer))
        check:
          PB.putUVarint(buffer, PBedgeValues[i]).isOk == true
        buffer[9] = buffer[9] or 0x80'u8
        buffer[10] = 0x01'u8
        let res = PB.getUVarint(buffer)
        check:
          res.isErr == true
          res.error == errors.OverflowError

  test "[LibP2P] Success edge cases test":
    var buffer = newSeq[byte]()
    var length = 0
    var value = 0'u64
    for i in 0..<len(LPedgeValues):
      buffer.setLen(LPedgeSizes[i])

      zeroMem(addr buffer[0], len(buffer))
      value = 0'u64

      check LP.putUVarint(buffer, LPedgeValues[i]).isOk == true
      let res = LP.getUVarint(buffer)
      check:
        res.isOk == true
        res.value.value == LPedgeValues[i]
        toHex(buffer) == LPedgeExpects[i]

  test "[LibP2P] Buffer Overrun edge cases test":
    var buffer = newSeq[byte]()
    var length = 0
    for i in 0..<len(LPedgeValues):
      buffer.setLen(PBedgeSizes[i] - 1)

      if len(buffer) > 0:
        zeroMem(addr buffer[0], len(buffer))
      let res2 = LP.putUVarint(buffer, PBedgeValues[i])
      check:
        res2.isErr == true
        res2.error == errors.OverrunError

  test "[LibP2P] Buffer Incomplete edge cases test":
    var buffer = newSeq[byte]()
    var length = 0
    var value = 0'u64
    for i in 0..<len(LPedgeValues):
      buffer.setLen(LPedgeSizes[i])
      zeroMem(addr buffer[0], len(buffer))

      check LP.putUVarint(buffer, LPedgeValues[i]).isOk == true
      buffer.setLen(len(buffer) - 1)
      let res = LP.getUVarint(buffer)
      check:
        res.isErr == true
        res.error == errors.IncompleteError

  test "[LibP2P] Integer Overflow 32bit test":
    var buffer = newSeq[byte]()
    var length = 0
    for i in 0..<len(LPedgeValues):
      if LPedgeSizes[i] > 5:
        var value = 0'u32
        buffer.setLen(LPedgeSizes[i])
        check LP.putUVarint(buffer, LPedgeValues[i]).isOk == true
        let res = LP.decodeUVarint(uint32, buffer)
        check:
          res.isErr == true
          res.error == errors.OverflowError

  test "[LibP2P] Integer Overflow 64bit test":
    var buffer = newSeq[byte]()
    var length = 0
    for i in 0..<len(LPedgeValues):
      if LPedgeSizes[i] > 8:
        var value = 0'u64
        buffer.setLen(LPedgeSizes[i] + 1)
        zeroMem(addr buffer[0], len(buffer))
        check LP.putUVarint(buffer, LPedgeValues[i]).isOk == true
        buffer[8] = buffer[9] or 0x80'u8
        buffer[9] = 0x01'u8
        let res = LP.getUVarint(buffer)
        check:
          res.isErr == true
          res.error == errors.OverflowError

  test "[LibP2P] Over 63bit test":
    var buffer = newSeq[byte](10)
    var length = 0
    let r1 = LP.putUVarint(buffer, 0x7FFF_FFFF_FFFF_FFFF'u64)
    let r2 = LP.putUVarint(buffer, 0x8000_0000_0000_0000'u64)
    let r3 = LP.putUVarint(buffer, 0xFFFF_FFFF_FFFF_FFFF'u64)
    check:
      r1.isOk == true
      r2.isErr == true
      r3.isErr == true
      r2.error == errors.OverflowError
      r3.error == errors.OverflowError
