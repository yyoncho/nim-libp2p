import unittest
import ../libp2p/multibase, ../libp2p/errors

const GoTestVectors = [
  [
    "identity",
    "\x00Decentralize everything!!!",
    "Decentralize everything!!!"
  ],
  # [
  #   "base16",
  #   "f446563656e7472616c697a652065766572797468696e67212121",
  #   "Decentralize everything!!!"
  # ],
  # [
  #   "base16upper",
  #   "F446563656E7472616C697A652065766572797468696E67212121",
  #   "Decentralize everything!!!"
  # ],
  [
    "base32",
    "birswgzloorzgc3djpjssazlwmvzhs5dinfxgoijbee",
    "Decentralize everything!!!"
  ],
  [
    "base32upper",
    "BIRSWGZLOORZGC3DJPJSSAZLWMVZHS5DINFXGOIJBEE",
    "Decentralize everything!!!"
  ],
  [
    "base32pad",
    "cirswgzloorzgc3djpjssazlwmvzhs5dinfxgoijbee======",
    "Decentralize everything!!!"
  ],
  [
    "base32padupper",
    "CIRSWGZLOORZGC3DJPJSSAZLWMVZHS5DINFXGOIJBEE======",
    "Decentralize everything!!!"
  ],
  [
    "base32hex",
    "v8him6pbeehp62r39f9ii0pbmclp7it38d5n6e89144",
    "Decentralize everything!!!"
  ],
  [
    "base32hexupper",
    "V8HIM6PBEEHP62R39F9II0PBMCLP7IT38D5N6E89144",
    "Decentralize everything!!!"
  ],
  [
    "base32hexpad",
    "t8him6pbeehp62r39f9ii0pbmclp7it38d5n6e89144======",
    "Decentralize everything!!!"
  ],
  [
    "base32hexpadupper",
    "T8HIM6PBEEHP62R39F9II0PBMCLP7IT38D5N6E89144======",
    "Decentralize everything!!!"
  ],
  [
    "base58btc",
    "z36UQrhJq9fNDS7DiAHM9YXqDHMPfr4EMArvt",
    "Decentralize everything!!!"
  ],
  [
    "base64",
    "mRGVjZW50cmFsaXplIGV2ZXJ5dGhpbmchISE",
    "Decentralize everything!!!"
  ],
  [
    "base64url",
    "uRGVjZW50cmFsaXplIGV2ZXJ5dGhpbmchISE",
    "Decentralize everything!!!"
  ],
  [
    "base64pad",
    "MRGVjZW50cmFsaXplIGV2ZXJ5dGhpbmchISE=",
    "Decentralize everything!!!"
  ],
  [
    "base64urlpad",
    "URGVjZW50cmFsaXplIGV2ZXJ5dGhpbmchISE=",
    "Decentralize everything!!!"
  ],
]

suite "MultiBase test suite":
  test "Zero-length data encoding/decoding test":
    var enc = newString(1)
    var dec = newSeq[byte]()
    var plain = newSeq[byte]()
    var olens: array[21, int]
    let r1 = MultiBase.encodedLength("identity", 0)
    let r2 = MultiBase.decodedLength('\x00', 0)
    let r3 = MultiBase.decodedLength('\x00', 1)
    check:
      r1.isOk == true
      r1.value == 1
      r2.isOk == false
      r2.error == errors.IncorrectEncodingError
      r3.isOk == true
      r3.value == 0

    let e1 = MultiBase.encode("identity", plain)
    # let e2 = MultiBase.encode("base1", plain)
    # let e3 = MultiBase.encode("base2", plain)
    # let e4 = MultiBase.encode("base8", plain)
    # let e5 = MultiBase.encode("base10", plain)
    # let e6 = MultiBase.encode("base16", plain)
    # let e7 = MultiBase.encode("base16upper", plain)
    let e8 = MultiBase.encode("base32hex", plain)
    let e9 = MultiBase.encode("base32hexupper", plain)
    let e10 = MultiBase.encode("base32hexpad", plain)
    let e11 = MultiBase.encode("base32hexpadupper", plain)
    let e12 = MultiBase.encode("base32", plain)
    let e13 = MultiBase.encode("base32upper", plain)
    let e14 = MultiBase.encode("base32pad", plain)
    let e15 = MultiBase.encode("base32padupper", plain)
    let e16 = MultiBase.encode("base58btc", plain)
    let e17 = MultiBase.encode("base58flickr", plain)
    let e18 = MultiBase.encode("base64", plain)
    let e19 = MultiBase.encode("base64pad", plain)
    let e20 = MultiBase.encode("base64url", plain)
    let e21 = MultiBase.encode("base64urlpad", plain)

    check:
      e1.isOk == true
      # e2.isOk == true
      # e3.isOk == true
      # e4.isOk == true
      # e5.isOk == true
      # e6.isOk == true
      # e7.isOk == true
      e8.isOk == true
      e9.isOk == true
      e10.isOk == true
      e11.isOk == true
      e12.isOk == true
      e13.isOk == true
      e14.isOk == true
      e15.isOk == true
      e16.isOk == true
      e17.isOk == true
      e18.isOk == true
      e19.isOk == true
      e20.isOk == true
      e21.isOk == true
      e1.value == "\x00"
      # e2.value == "1"
      # e3.value == "0"
      # e4.value == "7"
      # e5.value == "9"
      # e6.value == "f"
      # e7.value == "F"
      e8.value == "v"
      e9.value == "V"
      e10.value == "t"
      e11.value == "T"
      e12.value == "b"
      e13.value == "B"
      e14.value == "c"
      e15.value == "C"
      e16.value == "z"
      e17.value == "Z"
      e18.value == "m"
      e19.value == "M"
      e20.value == "u"
      e21.value == "U"

      MultiBase.Identity.encode(plain) == "\x00"
      # MultiBase.Base1.encode(plain) == "1"
      # MultiBase.Base2.encode(plain) == "0"
      # MultiBase.Base8.encode(plain) == "7"
      # MultiBase.Base10.encode(plain) == "9"
      # MultiBase.Base16.encode(plain) == "f"
      # MultiBase.Base16Upper.encode(plain) == "F"
      MultiBase.Base32Hex.encode(plain) == "v"
      MultiBase.Base32HexUpper.encode(plain) == "V"
      MultiBase.Base32HexPad.encode(plain) == "t"
      MultiBase.Base32HexPadUpper.encode(plain) == "T"
      MultiBase.Base32.encode(plain) == "b"
      MultiBase.Base32Upper.encode(plain) == "B"
      MultiBase.Base32Pad.encode(plain) == "c"
      MultiBase.Base32PadUpper.encode(plain) == "C"
      MultiBase.Base58Btc.encode(plain) == "z"
      MultiBase.Base58Flickr.encode(plain) == "Z"
      MultiBase.Base64.encode(plain) == "m"
      MultiBase.Base64Pad.encode(plain) == "M"
      MultiBase.Base64Url.encode(plain) == "u"
      MultiBase.Base64UrlPad.encode(plain) == "U"

      MultiBase.Identity.encodedLength(0) == 1
      # MultiBase.Base1.encodedLength(0) == 1
      # MultiBase.Base2.encodedLength(0) == 1
      # MultiBase.Base8.encodedLength(0) == 1
      # MultiBase.Base10.encodedLength(0) == 1
      # MultiBase.Base16.encodedLength(0) == 1
      # MultiBase.Base16Upper.encodedLength(0) == 1
      MultiBase.Base32Hex.encodedLength(0) == 1
      MultiBase.Base32HexUpper.encodedLength(0) == 1
      MultiBase.Base32HexPad.encodedLength(0) == 1
      MultiBase.Base32HexPadUpper.encodedLength(0) == 1
      MultiBase.Base32.encodedLength(0) == 1
      MultiBase.Base32Upper.encodedLength(0) == 1
      MultiBase.Base32Pad.encodedLength(0) == 1
      MultiBase.Base32PadUpper.encodedLength(0) == 1
      MultiBase.Base58Btc.encodedLength(0) == 1
      MultiBase.Base58Flickr.encodedLength(0) == 1
      MultiBase.Base64.encodedLength(0) == 1
      MultiBase.Base64Pad.encodedLength(0) == 1
      MultiBase.Base64Url.encodedLength(0) == 1
      MultiBase.Base64UrlPad.encodedLength(0) == 1

      MultiBase.Identity.decodedLength(1) == 0
      # MultiBase.Base1.decodedLength(1) == 0
      # MultiBase.Base2.decodedLength(1) == 0
      # MultiBase.Base8.decodedLength(1) == 0
      # MultiBase.Base10.decodedLength(1) == 0
      # MultiBase.Base16.decodedLength(1) == 0
      # MultiBase.Base16Upper.decodedLength(1) == 0
      MultiBase.Base32Hex.decodedLength(1) == 0
      MultiBase.Base32HexUpper.decodedLength(1) == 0
      MultiBase.Base32HexPad.decodedLength(1) == 0
      MultiBase.Base32HexPadUpper.decodedLength(1) == 0
      MultiBase.Base32.decodedLength(1) == 0
      MultiBase.Base32Upper.decodedLength(1) == 0
      MultiBase.Base32Pad.decodedLength(1) == 0
      MultiBase.Base32PadUpper.decodedLength(1) == 0
      MultiBase.Base58Btc.decodedLength(1) == 0
      MultiBase.Base58Flickr.decodedLength(1) == 0
      MultiBase.Base64.decodedLength(1) == 0
      MultiBase.Base64Pad.decodedLength(1) == 0
      MultiBase.Base64Url.decodedLength(1) == 0
      MultiBase.Base64UrlPad.decodedLength(1) == 0

    let d1 = MultiBase.decode("\x00")
    # let d2 = MultiBase.decode("1")
    # let d3 = MultiBase.decode("0")
    # let d4 = MultiBase.decode("7")
    # let d5 = MultiBase.decode("9")
    # let d6 = MultiBase.decode("f")
    # let d7 = MultiBase.decode("F")
    let d8 = MultiBase.decode("v")
    let d9 = MultiBase.decode("V")
    let d10 = MultiBase.decode("t")
    let d11 = MultiBase.decode("T")
    let d12 = MultiBase.decode("b")
    let d13 = MultiBase.decode("B")
    let d14 = MultiBase.decode("c")
    let d15 = MultiBase.decode("C")
    let d16 = MultiBase.decode("z")
    let d17 = MultiBase.decode("Z")
    let d18 = MultiBase.decode("m")
    let d19 = MultiBase.decode("M")
    let d20 = MultiBase.decode("u")
    let d21 = MultiBase.decode("U")
    check:
      d1.isOk == true
      # d2.isOk == true
      # d3.isOk == true
      # d4.isOk == true
      # d5.isOk == true
      # d6.isOk == true
      # d7.isOk == true
      d8.isOk == true
      d9.isOk == true
      d10.isOk == true
      d11.isOk == true
      d12.isOk == true
      d13.isOk == true
      d14.isOk == true
      d15.isOk == true
      d16.isOk == true
      d17.isOk == true
      d18.isOk == true
      d19.isOk == true
      d20.isOk == true
      d21.isOk == true
      len(d1.value) == 0
      # len(d2.value) == 0
      # len(d3.value) == 0
      # len(d4.value) == 0
      # len(d5.value) == 0
      # len(d6.value) == 0
      # len(d7.value) == 0
      len(d8.value) == 0
      len(d9.value) == 0
      len(d10.value) == 0
      len(d11.value) == 0
      len(d12.value) == 0
      len(d13.value) == 0
      len(d14.value) == 0
      len(d15.value) == 0
      len(d16.value) == 0
      len(d17.value) == 0
      len(d18.value) == 0
      len(d19.value) == 0
      len(d20.value) == 0
      len(d21.value) == 0

    let n1 = MultiBase.encode("identity", plain, enc)
    check:
      n1.isOk == true
      n1.value == 1
      enc == "\x00"
    # let n2 = MultiBase.encode("base1", plain, enc)
    # check:
    #   n2.isOk == true
    #   n2.value == 1
    #   enc == "1"
    # let n3 = MultiBase.encode("base2", plain, enc)
    # check:
    #   n3.isOk == true
    #   n3.value == 1
    #   enc == "0"
    # let n4 = MultiBase.encode("base8", plain, enc)
    # check:
    #   n4.isOk == true
    #   n4.value == 1
    #   enc == "7"
    # let n5 = MultiBase.encode("base10", plain, enc)
    # check:
    #   n5.isOk == true
    #   n5.value == 1
    #   enc == "9"
    # let n6 = MultiBase.encode("base16", plain, enc)
    # check:
    #   n6.isOk == true
    #   n6.value == 1
    #   enc == "f"
    # let n7 = MultiBase.encode("base16upper", plain, enc)
    # check:
    #   n7.isOk == true
    #   n7.value == 1
    #   enc == "F"
    let n8 = MultiBase.encode("base32hex", plain, enc)
    check:
      n8.isOk == true
      n8.value == 1
      enc == "v"
    let n9 = MultiBase.encode("base32hexupper", plain, enc)
    check:
      n9.isOk == true
      n9.value == 1
      enc == "V"
    let n10 = MultiBase.encode("base32hexpad", plain, enc)
    check:
      n10.isOk == true
      n10.value == 1
      enc == "t"
    let n11 = MultiBase.encode("base32hexpadupper", plain, enc)
    check:
      n11.isOk == true
      n11.value == 1
      enc == "T"
    let n12 = MultiBase.encode("base32", plain, enc)
    check:
      n12.isOk == true
      n12.value == 1
      enc == "b"
    let n13 = MultiBase.encode("base32upper", plain, enc)
    check:
      n13.isOk == true
      n13.value == 1
      enc == "B"
    let n14 = MultiBase.encode("base32pad", plain, enc)
    check:
      n14.isOk == true
      n14.value == 1
      enc == "c"
    let n15 = MultiBase.encode("base32padupper", plain, enc)
    check:
      n15.isOk == true
      n15.value == 1
      enc == "C"
    let n16 = MultiBase.encode("base58btc", plain, enc)
    check:
      n16.isOk == true
      n16.value == 1
      enc == "z"
    let n17 = MultiBase.encode("base58flickr", plain, enc)
    check:
      n17.isOk == true
      n17.value == 1
      enc == "Z"
    let n18 = MultiBase.encode("base64", plain, enc)
    check:
      n18.isOk == true
      n18.value == 1
      enc == "m"
    let n19 = MultiBase.encode("base64pad", plain, enc)
    check:
      n19.isOk == true
      n19.value == 1
      enc == "M"
    let n20 = MultiBase.encode("base64url", plain, enc)
    check:
      n20.isOk == true
      n20.value == 1
      enc == "u"
    let n21 = MultiBase.encode("base64urlpad", plain, enc)
    check:
      n21.isOk == true
      n21.value == 1
      enc == "U"

    let c0 = MultiBase.decode("", dec)
    check:
      c0.isErr == true
      c0.error == errors.IncorrectEncodingError
    let c1 = MultiBase.decode("\x00", dec)
    check:
      c1.isOk == true
      c1.value == 0
    # let c2 = MultiBase.decode("1", dec)
    # check:
    #   c2.isOk == true
    #   c2.value == 0
    # let c3 = MultiBase.decode("0", dec)
    # check:
    #   c3.isOk == true
    #   c3.value == 0
    # let c4 = MultiBase.decode("7", dec)
    # check:
    #   c4.isOk == true
    #   c4.value == 0
    # let c5 = MultiBase.decode("9", dec)
    # check:
    #   c5.isOk == true
    #   c5.value == 0
    # let c6 = MultiBase.decode("f", dec)
    # check:
    #   c6.isOk == true
    #   c6.value == 0
    # let c7 = MultiBase.decode("F", dec)
    # check:
    #   c7.isOk == true
    #   c7.value == 0
    let c8 = MultiBase.decode("v", dec)
    check:
      c8.isOk == true
      c8.value == 0
    let c9 = MultiBase.decode("V", dec)
    check:
      c9.isOk == true
      c9.value == 0
    let c10 = MultiBase.decode("t", dec)
    check:
      c10.isOk == true
      c10.value == 0
    let c11 = MultiBase.decode("T", dec)
    check:
      c11.isOk == true
      c11.value == 0
    let c12 = MultiBase.decode("b", dec)
    check:
      c12.isOk == true
      c12.value == 0
    let c13 = MultiBase.decode("B", dec)
    check:
      c13.isOk == true
      c13.value == 0
    let c14 = MultiBase.decode("c", dec)
    check:
      c14.isOk == true
      c14.value == 0
    let c15 = MultiBase.decode("C", dec)
    check:
      c15.isOk == true
      c15.value == 0
    let c16 = MultiBase.decode("z", dec)
    check:
      c16.isOk == true
      c16.value == 0
    let c17 = MultiBase.decode("Z", dec)
    check:
      c17.isOk == true
      c17.value == 0
    let c18 = MultiBase.decode("m", dec)
    check:
      c18.isOk == true
      c18.value == 0
    let c19 = MultiBase.decode("M", dec)
    check:
      c19.isOk == true
      c19.value == 0
    let c20 = MultiBase.decode("u", dec)
    check:
      c20.isOk == true
      c20.value == 0
    let c21 = MultiBase.decode("U", dec)
    check:
      c21.isOk == true
      c21.value == 0

  test "go-multibase test vectors":
    for item in GoTestVectors:
      let encoding = item[0]
      let encoded = item[1]
      var expect = item[2]
      var bexpect = cast[seq[byte]](expect)
      var outlen = 0
      let e1 = MultiBase.encode(encoding, bexpect)
      let e2 = MultiBase.decode(encoded)
      check:
        e1.isOk == true
        e2.isOk == true
        e1.value == encoded
        e2.value == bexpect

      let e3 = MultiBase.encodedLength(encoding, len(expect))
      check e3.isOk == true
      var ebuffer = newString(e3.value)
      let e4 = MultiBase.encode(encoding, bexpect, ebuffer)
      check e4.isOk == true
      ebuffer.setLen(e4.value)
      check encoded == ebuffer

      let e5 = MultiBase.decodedLength(encoded[0], len(encoded))
      check e5.isOk == true
      var dbuffer = newSeq[byte](e5.value)
      let e6 = MultiBase.decode(encoded, dbuffer)
      check e6.isOk == true
      dbuffer.setLen(e6.value)
      check bexpect == dbuffer

  test "Unknown codec test":
    var data = @[0x00'u8, 0x01'u8]
    var ebuffer = newString(100)
    var dbuffer = newSeq[byte](100)
    var outlen = 0
    let r1 = MultiBase.encode("unknown", data, ebuffer)
    let r2 = MultiBase.decode("\x01\x00", dbuffer)
    check:
      r1.isErr == true
      r2.isErr == true
      r1.error == errors.NoSupportError
      r2.error == errors.NoSupportError

    let r3 = MultiBase.encode("unknown", data)
    let r4 = MultiBase.decode("\x01\x00")
    check:
      r3.isErr == true
      r4.isErr == true
      r3.error == errors.NoSupportError
      r4.error == errors.NoSupportError
