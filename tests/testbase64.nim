import unittest
import ../libp2p/base64, ../libp2p/errors

const TVBasePadding = [
  ["f", "Zg=="],
  ["fo", "Zm8="],
  ["foo", "Zm9v"],
  ["foob", "Zm9vYg=="],
  ["fooba", "Zm9vYmE="],
  ["foobar", "Zm9vYmFy"]
]

const TVBaseNoPadding = [
  ["f", "Zg"],
  ["fo", "Zm8"],
  ["foo", "Zm9v"],
  ["foob", "Zm9vYg"],
  ["fooba", "Zm9vYmE"],
  ["foobar", "Zm9vYmFy"]
]

suite "BASE64 encoding test suite":
  test "Empty seq/string test":
    var empty1 = newSeq[byte]()
    var empty2 = ""
    var encoded = newString(16)
    var decoded = newSeq[byte](16)

    let e1 = Base64.encode(empty1)
    let e2 = Base64Url.encode(empty1)
    let e3 = Base64Pad.encode(empty1)
    let e4 = Base64UrlPad.encode(empty1)
    let e5 = Base64.encode(empty1, encoded)
    let e6 = Base64Url.encode(empty1, encoded)
    let e7 = Base64Pad.encode(empty1, encoded)
    let e8 = Base64UrlPad.encode(empty1, encoded)

    check:
      e5.isOk == true
      e6.isOk == true
      e7.isOk == true
      e8.isOk == true
      len(e1) == 0
      len(e2) == 0
      len(e3) == 0
      len(e4) == 0
      e5.value == 0
      e6.value == 0
      e7.value == 0
      e8.value == 0

    let d1 = Base64.decode("")
    let d2 = Base64Url.decode("")
    let d3 = Base64Pad.decode("")
    let d4 = Base64UrlPad.decode("")
    let d5 = Base64.decode(empty2, decoded)
    let d6 = Base64Url.decode(empty2, decoded)
    let d7 = Base64Pad.decode(empty2, decoded)
    let d8 = Base64UrlPad.decode(empty2, decoded)

    check:
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
      d5.value == 0
      d6.value == 0
      d7.value == 0
      d8.value == 0

  test "Zero test":
    var s = newString(256)
    for i in 0..255:
      s[i] = 'A'
    var buffer: array[256, byte]
    for i in 0..255:
      var a = Base64.encode(buffer.toOpenArray(0, i))
      var b = Base64.decode(a)
      check:
        b.isOk == true
        b.value == buffer[0..i]

  test "Leading zero test":
    var buffer: array[256, byte]
    for i in 0..255:
      buffer[255] = byte(i)
      var a = Base64.encode(buffer)
      var b = Base64.decode(a)
      check:
        b.isOk == true
        equalMem(addr buffer[0], addr b.value[0], 256) == true

  proc testVector(bt64: typedesc[Base64Types],
                  vectors: array[6, array[2, string]]): bool =
    for item in vectors:
      let plain = cast[seq[byte]](item[0])
      let expect = item[1]

      var e1 = bt64.encode(plain)
      var e2 = newString(bt64.encodedLength(len(plain)))
      var e3 = bt64.encode(plain, e2)

      if e3.isErr:
        return false

      e2.setLen(e3.value)

      if (e1 != expect) or (e2 != expect):
        return false

      var d1 = bt64.decode(expect)
      var d2 = newSeq[byte](bt64.decodedLength(len(expect)))
      var d3 = bt64.decode(expect, d2)

      if d1.isErr or d3.isErr:
        return false

      d2.setLen(d3.value)

      if (d1.value != plain) or (d2 != plain):
        return false

      return true

  test "BASE64 padding test vectors":
    check Base64Pad.testVector(TVBasePadding) == true

  test "BASE64 no padding test vectors":
    check Base64.testVector(TVBaseNoPadding) == true

  test "Buffer Overrun test":
    var encres = ""
    var decres: seq[byte] = @[]
    let r1 = Base64.encode([0'u8], encres)
    let r2 = Base64.decode("AA", decres)
    check:
      r1.isErr == true
      r2.isErr == true
      r1.error == errors.OverrunError
      r2.error == errors.OverrunError

  test "Incorrect test":
    var decres = newSeq[byte](10)
    let r1 = Base64.decode("A", decres)
    let r2 = Base64.decode("AAAAA", decres)
    let r3 = Base64.decode("!", decres)
    let r4 = Base64.decode("!!", decres)
    let r5 = Base64.decode("AA==", decres)
    let r6 = Base64.decode("_-", decres)
    let r7 = Base64Url.decode("/+", decres)
    check:
      r1.isErr == true
      r2.isErr == true
      r3.isErr == true
      r4.isErr == true
      r5.isErr == true
      r6.isErr == true
      r7.isErr == true
      r1.error == errors.IncorrectEncodingError
      r2.error == errors.IncorrectEncodingError
      r3.error == errors.IncorrectEncodingError
      r4.error == errors.IncorrectEncodingError
      r5.error == errors.IncorrectEncodingError
      r6.error == errors.IncorrectEncodingError
      r7.error == errors.IncorrectEncodingError
