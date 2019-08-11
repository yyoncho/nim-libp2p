import unittest
import ../libp2p/base32, ../libp2p/errors

const TVBaseUpperPadding = [
  ["f", "MY======"],
  ["fo", "MZXQ===="],
  ["foo", "MZXW6==="],
  ["foob", "MZXW6YQ="],
  ["fooba", "MZXW6YTB"],
  ["foobar", "MZXW6YTBOI======"]
]

const TVBaseUpperNoPadding = [
  ["f", "MY"],
  ["fo", "MZXQ"],
  ["foo", "MZXW6"],
  ["foob", "MZXW6YQ"],
  ["fooba", "MZXW6YTB"],
  ["foobar", "MZXW6YTBOI"]
]

const TVBaseLowerPadding = [
  ["f", "my======"],
  ["fo", "mzxq===="],
  ["foo", "mzxw6==="],
  ["foob", "mzxw6yq="],
  ["fooba", "mzxw6ytb"],
  ["foobar", "mzxw6ytboi======"]
]

const TVBaseLowerNoPadding = [
  ["f", "my"],
  ["fo", "mzxq"],
  ["foo", "mzxw6"],
  ["foob", "mzxw6yq"],
  ["fooba", "mzxw6ytb"],
  ["foobar", "mzxw6ytboi"]
]

const TVHexUpperPadding = [
  ["f", "CO======"],
  ["fo", "CPNG===="],
  ["foo", "CPNMU==="],
  ["foob", "CPNMUOG="],
  ["fooba", "CPNMUOJ1"],
  ["foobar", "CPNMUOJ1E8======"]
]

const TVHexUpperNoPadding = [
  ["f", "CO"],
  ["fo", "CPNG"],
  ["foo", "CPNMU"],
  ["foob", "CPNMUOG"],
  ["fooba", "CPNMUOJ1"],
  ["foobar", "CPNMUOJ1E8"]
]

const TVHexLowerPadding = [
  ["f", "co======"],
  ["fo", "cpng===="],
  ["foo", "cpnmu==="],
  ["foob", "cpnmuog="],
  ["fooba", "cpnmuoj1"],
  ["foobar", "cpnmuoj1e8======"]
]

const TVHexLowerNoPadding = [
  ["f", "co"],
  ["fo", "cpng"],
  ["foo", "cpnmu"],
  ["foob", "cpnmuog"],
  ["fooba", "cpnmuoj1"],
  ["foobar", "cpnmuoj1e8"]
]

suite "BASE32 encoding test suite":
  test "Empty seq/string test":
    var empty1 = newSeq[byte]()
    var empty2 = ""
    var encoded = newString(16)
    var decoded = newSeq[byte](16)

    check:
      Base32Upper.encode(empty1) == ""
      Base32Lower.encode(empty1) == ""
      Base32UpperPad.encode(empty1) == ""
      Base32LowerPad.encode(empty1) == ""
      HexBase32Upper.encode(empty1) == ""
      HexBase32Lower.encode(empty1) == ""
      HexBase32UpperPad.encode(empty1) == ""
      HexBase32LowerPad.encode(empty1) == ""
      Base32Upper.encode(empty1, encoded).isOk == true
      Base32Lower.encode(empty1, encoded).isOk == true
      Base32UpperPad.encode(empty1, encoded).isOk == true
      Base32LowerPad.encode(empty1, encoded).isOk == true
      HexBase32Upper.encode(empty1, encoded).isOk == true
      HexBase32Lower.encode(empty1, encoded).isOk == true
      HexBase32UpperPad.encode(empty1, encoded).isOk == true
      HexBase32LowerPad.encode(empty1, encoded).isOk == true

    var d1 = Base32Upper.decode("")
    var d2 = Base32Lower.decode("")
    var d3 = Base32UpperPad.decode("")
    var d4 = Base32LowerPad.decode("")
    var d5 = HexBase32Upper.decode("")
    var d6 = HexBase32Lower.decode("")
    var d7 = HexBase32UpperPad.decode("")
    var d8 = HexBase32LowerPad.decode("")
    check:
      Base32Upper.decode(empty2, decoded).isOk == true
      Base32Lower.decode(empty2, decoded).isOk == true
      Base32UpperPad.decode(empty2, decoded).isOk == true
      Base32LowerPad.decode(empty2, decoded).isOk == true
      HexBase32Upper.decode(empty2, decoded).isOk == true
      HexBase32Lower.decode(empty2, decoded).isOk == true
      HexBase32UpperPad.decode(empty2, decoded).isOk == true
      HexBase32LowerPad.decode(empty2, decoded).isOk == true
      d1.isOk == true
      d2.isOk == true
      d3.isOk == true
      d4.isOk == true
      d5.isOk == true
      d6.isOk == true
      d7.isOk == true
      d8.isOk == true
      len(d1.value) == 0
      len(d2.value) == 0
      len(d3.value) == 0
      len(d4.value) == 0
      len(d5.value) == 0
      len(d6.value) == 0
      len(d7.value) == 0
      len(d8.value) == 0

  test "Zero test":
    var s = newString(256)
    for i in 0..255:
      s[i] = 'A'
    var buffer: array[256, byte]
    for i in 0..255:
      var a = Base32.encode(buffer.toOpenArray(0, i))
      var b = Base32.decode(a)
      check:
        b.isOk == true
        b.value == buffer[0..i]

  test "Leading zero test":
    var buffer: array[256, byte]
    for i in 0..255:
      buffer[255] = byte(i)
      var a = Base32.encode(buffer)
      var b = Base32.decode(a)
      check:
        b.isOk == true
        equalMem(addr buffer[0], addr b.value[0], 256) == true

  proc testVector(bt32: typedesc[Base32Types],
                  vectors: array[6, array[2, string]]): bool =
    for item in vectors:
      let plain = cast[seq[byte]](item[0])
      let expect = item[1]

      var e1 = bt32.encode(plain)
      var e2 = newString(bt32.encodedLength(len(plain)))
      var e3 = bt32.encode(plain, e2)

      if e3.isErr:
        return false

      e2.setLen(e3.value)

      if (e1 != expect) or (e2 != expect):
        return false

      var d1 = bt32.decode(expect)
      var d2 = newSeq[byte](bt32.decodedLength(len(expect)))
      var d3 = bt32.decode(expect, d2)

      if d1.isErr or d3.isErr:
        return false

      d2.setLen(d3.value)

      if (d1.value != plain) or (d2 != plain):
        return false

      return true

  test "BASE32 uppercase padding test vectors":
    check Base32UpperPad.testVector(TVBaseUpperPadding) == true

  test "BASE32 lowercase padding test vectors":
    check Base32LowerPad.testVector(TVBaseLowerPadding) == true

  test "BASE32 uppercase no-padding test vectors":
    check Base32Upper.testVector(TVBaseUpperNoPadding) == true

  test "BASE32 lowercase no-padding test vectors":
    check Base32Lower.testVector(TVBaseLowerNoPadding) == true

  test "HEX-BASE32 uppercase padding test vectors":
    check HexBase32UpperPad.testVector(TVHexUpperPadding) == true

  test "HEX-BASE32 lowercase padding test vectors":
    check HexBase32LowerPad.testVector(TVHexLowerPadding) == true

  test "HEX-BASE32 uppercase no-padding test vectors":
    check HexBase32Upper.testVector(TVHexUpperNoPadding) == true

  test "HEX-BASE32 lowercase no-padding test vectors":
    check HexBase32Lower.testVector(TVHexLowerNoPadding) == true

  test "Buffer Overrun test":
    var encres = ""
    var decres: seq[byte] = @[]
    let r1 = Base32.encode([0'u8], encres)
    let r2 = Base32.decode("AA", decres)
    check:
      r1.isErr == true
      r2.isErr == true
      r1.error == errors.OverrunError
      r2.error == errors.OverrunError

  test "Incorrect test":
    var decres = newSeq[byte](10)
    let r1 = Base32.decode("A", decres)
    let r2 = Base32.decode("AAA", decres)
    let r3 = Base32.decode("AAAAAA", decres)
    let r4 = Base32Upper.decode("aa", decres)
    let r5 = Base32Upper.decode("11", decres)
    let r6 = Base32Lower.decode("AA", decres)
    let r7 = Base32Lower.decode("11", decres)
    let r8 = HexBase32Upper.decode("aa", decres)
    let r9 = HexBase32Upper.decode("WW", decres)
    let rA = HexBase32Lower.decode("AA", decres)
    let rB = HexBase32Lower.decode("ww", decres)
    check:
      r1.isErr == true
      r2.isErr == true
      r3.isErr == true
      r4.isErr == true
      r5.isErr == true
      r6.isErr == true
      r7.isErr == true
      r8.isErr == true
      r9.isErr == true
      rA.isErr == true
      rB.isErr == true
      r1.error == errors.IncorrectEncodingError
      r2.error == errors.IncorrectEncodingError
      r3.error == errors.IncorrectEncodingError
      r4.error == errors.IncorrectEncodingError
      r5.error == errors.IncorrectEncodingError
      r6.error == errors.IncorrectEncodingError
      r7.error == errors.IncorrectEncodingError
      r8.error == errors.IncorrectEncodingError
      r9.error == errors.IncorrectEncodingError
      rA.error == errors.IncorrectEncodingError
      rB.error == errors.IncorrectEncodingError
