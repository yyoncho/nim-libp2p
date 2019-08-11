## Nim-Libp2p
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

## This module implements MultiBase.
##
## TODO:
## base32z, base16, base10, base8, base2, base1
import tables, strutils
import base32, base58, base64, errors
export errors

type
  MultiBase* {.pure.} = enum
    ## Commented bases are not yet supported
    NoSupport,
    Identity,
    # Base1, Base2, Base8, Base10,
    # Base16, Base16Upper,
    Base32Hex, Base32HexUpper, Base32HexPad, Base32HexPadUpper,
    Base32, Base32Upper, Base32Pad, Base32PadUpper,
    #Base32z,
    Base58Flickr, Base58Btc,
    Base64, Base64Pad, Base64Url, Base64UrlPad

  MBCodec = object
    code: char
    base: MultiBase
    name: string
    encr: proc(i: openarray[byte],
               o: var openarray[char]): Result[int,
                                               errors.Error] {.nimcall, gcsafe.}
    decr: proc(i: openarray[char],
               o: var openarray[byte]): Result[int,
                                               errors.Error] {.nimcall, gcsafe.}
    encl: proc(length: int): int {.nimcall, gcsafe.}
    decl: proc(length: int): int {.nimcall, gcsafe.}

proc idd(inbytes: openarray[char],
         outbytes: var openarray[byte]): Result[int, errors.Error] =
  let length = len(inbytes)
  if length > len(outbytes):
    result.err(errors.OverrunError)
  else:
    copyMem(addr outbytes[0], unsafeAddr inbytes[0], length)
    result.ok(length)

proc ide(inbytes: openarray[byte],
         outbytes: var openarray[char]): Result[int, errors.Error] =
  let length = len(inbytes)
  if length > len(outbytes):
    result.err(errors.OverrunError)
  else:
    copyMem(addr outbytes[0], unsafeAddr inbytes[0], length)
    result.ok(length)

proc idel(length: int): int = length
proc iddl(length: int): int = length

proc b16d(inbytes: openarray[char],
          outbytes: var openarray[byte]): Result[int, errors.Error] =
  result.err(errors.NoSupportError)

proc b16e(inbytes: openarray[byte],
          outbytes: var openarray[char]): Result[int, errors.Error] =
  result.err(errors.NoSupportError)

proc b16ud(inbytes: openarray[char],
           outbytes: var openarray[byte]): Result[int, errors.Error] =
  result.err(errors.NoSupportError)

proc b16ue(inbytes: openarray[byte],
           outbytes: var openarray[char]): Result[int, errors.Error] =
  result.err(errors.NoSupportError)

proc b16el(length: int): int = length shl 1
proc b16dl(length: int): int = (length + 1) div 2

proc b32hd(inbytes: openarray[char],
           outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = HexBase32Lower.decode(inbytes, outbytes)

proc b32he(inbytes: openarray[byte],
           outbytes: var openarray[char]): Result[int, errors.Error] =
  result = HexBase32Lower.encode(inbytes, outbytes)

proc b32hud(inbytes: openarray[char],
            outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = HexBase32Upper.decode(inbytes, outbytes)

proc b32hue(inbytes: openarray[byte],
            outbytes: var openarray[char]): Result[int, errors.Error] =
  result = HexBase32Upper.encode(inbytes, outbytes)

proc b32hpd(inbytes: openarray[char],
            outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = HexBase32LowerPad.decode(inbytes, outbytes)

proc b32hpe(inbytes: openarray[byte],
            outbytes: var openarray[char]): Result[int, errors.Error] =
  result = HexBase32LowerPad.encode(inbytes, outbytes)

proc b32hpud(inbytes: openarray[char],
             outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = HexBase32UpperPad.decode(inbytes, outbytes)

proc b32hpue(inbytes: openarray[byte],
             outbytes: var openarray[char]): Result[int, errors.Error] =
  result = HexBase32UpperPad.encode(inbytes, outbytes)

proc b32d(inbytes: openarray[char],
          outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = Base32Lower.decode(inbytes, outbytes)

proc b32e(inbytes: openarray[byte],
          outbytes: var openarray[char]): Result[int, errors.Error] =
  result = Base32Lower.encode(inbytes, outbytes)

proc b32ud(inbytes: openarray[char],
           outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = Base32Upper.decode(inbytes, outbytes)

proc b32ue(inbytes: openarray[byte],
           outbytes: var openarray[char]): Result[int, errors.Error] =
  result = Base32Upper.encode(inbytes, outbytes)

proc b32pd(inbytes: openarray[char],
           outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = Base32LowerPad.decode(inbytes, outbytes)

proc b32pe(inbytes: openarray[byte],
           outbytes: var openarray[char]): Result[int, errors.Error] =
  result = Base32LowerPad.encode(inbytes, outbytes)

proc b32pud(inbytes: openarray[char],
            outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = Base32UpperPad.decode(inbytes, outbytes)

proc b32pue(inbytes: openarray[byte],
            outbytes: var openarray[char]): Result[int, errors.Error] =
  result = Base32UpperPad.encode(inbytes, outbytes)

proc b32el(length: int): int = Base32Lower.encodedLength(length)
proc b32dl(length: int): int = Base32Lower.decodedLength(length)
proc b32pel(length: int): int = Base32LowerPad.encodedLength(length)
proc b32pdl(length: int): int = Base32LowerPad.decodedLength(length)

proc b58fd(inbytes: openarray[char],
           outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = FLCBase58.decode(inbytes, outbytes)

proc b58fe(inbytes: openarray[byte],
           outbytes: var openarray[char]): Result[int, errors.Error] =
  result = FLCBase58.encode(inbytes, outbytes)

proc b58bd(inbytes: openarray[char],
           outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = BTCBase58.decode(inbytes, outbytes)

proc b58be(inbytes: openarray[byte],
           outbytes: var openarray[char]): Result[int, errors.Error] =
  result = BTCBase58.encode(inbytes, outbytes)

proc b58el(length: int): int = Base58.encodedLength(length)
proc b58dl(length: int): int = Base58.decodedLength(length)

proc b64el(length: int): int = Base64.encodedLength(length)
proc b64dl(length: int): int = Base64.decodedLength(length)
proc b64pel(length: int): int = Base64Pad.encodedLength(length)
proc b64pdl(length: int): int = Base64Pad.decodedLength(length)

proc b64e(inbytes: openarray[byte],
          outbytes: var openarray[char]): Result[int, errors.Error] =
  result = Base64.encode(inbytes, outbytes)

proc b64d(inbytes: openarray[char],
          outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = Base64.decode(inbytes, outbytes)

proc b64pe(inbytes: openarray[byte],
           outbytes: var openarray[char]): Result[int, errors.Error] =
  result = Base64Pad.encode(inbytes, outbytes)

proc b64pd(inbytes: openarray[char],
           outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = Base64Pad.decode(inbytes, outbytes)

proc b64ue(inbytes: openarray[byte],
           outbytes: var openarray[char]): Result[int, errors.Error] =
  result = Base64Url.encode(inbytes, outbytes)

proc b64ud(inbytes: openarray[char],
           outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = Base64Url.decode(inbytes, outbytes)

proc b64upe(inbytes: openarray[byte],
            outbytes: var openarray[char]): Result[int, errors.Error] =
  result = Base64UrlPad.encode(inbytes, outbytes)

proc b64upd(inbytes: openarray[char],
            outbytes: var openarray[byte]): Result[int, errors.Error] =
  result = Base64UrlPad.decode(inbytes, outbytes)

const
  MultibaseCodecs = [
    MBCodec(name: "identity", code: chr(0x00), base: MultiBase.Identity,
      decr: idd, encr: ide, decl: iddl, encl: idel
    ),
    MBCodec(name: "base1", code: '1'),
    MBCodec(name: "base2", code: '0'),
    MBCodec(name: "base8", code: '7'),
    MBCodec(name: "base10", code: '9'),
    MBCodec(name: "base16", code: 'f',
      decr: b16d, encr: b16e, decl: b16dl, encl: b16el
    ),
    MBCodec(name: "base16upper", code: 'F',
      decr: b16ud, encr: b16ue, decl: b16dl, encl: b16el
    ),
    MBCodec(name: "base32hex", code: 'v', base: MultiBase.Base32Hex,
      decr: b32hd, encr: b32he, decl: b32dl, encl: b32el
    ),
    MBCodec(name: "base32hexupper", code: 'V', base: MultiBase.Base32HexUpper,
      decr: b32hud, encr: b32hue, decl: b32dl, encl: b32el
    ),
    MBCodec(name: "base32hexpad", code: 't', base: MultiBase.Base32HexPad,
      decr: b32hpd, encr: b32hpe, decl: b32pdl, encl: b32pel
    ),
    MBCodec(name: "base32hexpadupper", code: 'T',
      base: MultiBase.Base32HexPadUpper,
      decr: b32hpud, encr: b32hpue, decl: b32pdl, encl: b32pel
    ),
    MBCodec(name: "base32", code: 'b', base: MultiBase.Base32,
      decr: b32d, encr: b32e, decl: b32dl, encl: b32el
    ),
    MBCodec(name: "base32upper", code: 'B', base: MultiBase.Base32Upper,
      decr: b32ud, encr: b32ue, decl: b32dl, encl: b32el
    ),
    MBCodec(name: "base32pad", code: 'c', base: MultiBase.Base32Pad,
      decr: b32pd, encr: b32pe, decl: b32pdl, encl: b32pel
    ),
    MBCodec(name: "base32padupper", code: 'C', base: MultiBase.Base32PadUpper,
      decr: b32pud, encr: b32pue, decl: b32pdl, encl: b32pel
    ),
    MBCodec(name: "base32z", code: 'h'),
    MBCodec(name: "base58flickr", code: 'Z', base: MultiBase.Base58Flickr,
      decr: b58fd, encr: b58fe, decl: b58dl, encl: b58el
    ),
    MBCodec(name: "base58btc", code: 'z', base: MultiBase.Base58Btc,
      decr: b58bd, encr: b58be, decl: b58dl, encl: b58el
    ),
    MBCodec(name: "base64", code: 'm', base: MultiBase.Base64,
      decr: b64d, encr: b64e, decl: b64dl, encl: b64el
    ),
    MBCodec(name: "base64pad", code: 'M', base: MultiBase.Base64Pad,
      decr: b64pd, encr: b64pe, decl: b64pdl, encl: b64pel
    ),
    MBCodec(name: "base64url", code: 'u', base: MultiBase.Base64Url,
      decr: b64ud, encr: b64ue, decl: b64dl, encl: b64el
    ),
    MBCodec(name: "base64urlpad", code: 'U', base: MultiBase.Base64UrlPad,
      decr: b64upd, encr: b64upe, decl: b64pdl, encl: b64pel
    )
  ]

proc initMultiBaseCodeTable(): Table[char, MBCodec] {.compileTime.} =
  result = initTable[char, MBCodec]()
  for item in MultibaseCodecs:
    result[item.code] = item

proc initMultiBaseNameTable(): Table[string, MBCodec] {.compileTime.} =
  result = initTable[string, MBCodec]()
  for item in MultibaseCodecs:
    result[item.name] = item

proc initMultiBaseTable(): Table[MultiBase, MBCodec] {.compileTime.} =
  result = initTable[MultiBase, MBCodec]()
  for item in MultibaseCodecs:
    result[item.base] = item

const
  CodeMultibases = initMultiBaseCodeTable()
  NameMultibases = initMultiBaseNameTable()
  BaseMultibases = initMultiBaseTable()

proc encodedLength*(mbtype: typedesc[MultiBase], encoding: string,
                    length: int): Result[int, errors.Error] =
  ## Return estimated size of buffer to store MultiBase encoded value with
  ## encoding ``encoding`` of length ``length``.
  let mb = NameMultibases.getOrDefault(encoding)
  if len(mb.name) == 0 or isNil(mb.encl):
    result.err(errors.NoSupportError)
  else:
    if length <= 0:
      result.ok(1)
    else:
      result.ok(mb.encl(length) + 1)

proc encodedLength*(encoding: MultiBase, length: int): int {.inline.} =
  ## Return estimated size of buffer to store MultiBase encoded value with
  ## encoding ``encoding`` of length ``length``.
  let mb = BaseMultibases.getOrDefault(encoding)
  if length <= 0:
    result = 1
  else:
    result = mb.encl(length) + 1

proc decodedLength*(mbtype: typedesc[MultiBase], encoding: char,
                    length: int): Result[int, errors.Error] =
  ## Return estimated size of buffer to store MultiBase decoded value with
  ## encoding character ``encoding`` of length ``length``.
  let mb = CodeMultibases.getOrDefault(encoding)
  if len(mb.name) == 0 or isNil(mb.decl):
    result.err(errors.NoSupportError)
  else:
    if length == 1:
      result.ok(0)
    elif length < 1:
      result.err(errors.IncorrectEncodingError)
    else:
      result.ok(mb.decl(length - 1))

proc decodedLength*(encoding: MultiBase, length: int): int {.inline.} =
  ## Return estimated size of buffer to store MultiBase decoded value with
  ## encoding character ``encoding`` of length ``length``.
  let mb = BaseMultibases.getOrDefault(encoding)
  if length == 1:
    result = 0
  else:
    result = mb.decl(length - 1)

proc encode*(mbtype: typedesc[MultiBase], encoding: string,
             inbytes: openarray[byte],
             outbytes: var openarray[char]): Result[int, errors.Error] =
  ## Encode array ``inbytes`` using MultiBase encoding scheme ``encoding`` and
  ## store encoded value to ``outbytes``.
  ##
  ## On success procedure returns number of bytes stored in ``outbytes`` array.
  let mb = NameMultibases.getOrDefault(encoding)
  if len(mb.name) == 0:
    result.err(errors.NoSupportError)
    return
  if isNil(mb.encr) or isNil(mb.encl):
    result.err(errors.NoSupportError)
    return

  if len(outbytes) > 1:
    let res = mb.encr(inbytes, outbytes.toOpenArray(1, len(outbytes) - 1))
    if res.isOk:
      outbytes[0] = mb.code
      result.ok(res.value + 1)
    else:
      result.err(res.error)
  else:
    if len(inbytes) == 0 and len(outbytes) >= 1:
      outbytes[0] = mb.code
      result.ok(1)
    else:
      result.err(errors.OverrunError)

proc decode*(mbtype: typedesc[MultiBase], inbytes: openarray[char],
             outbytes: var openarray[byte]): Result[int, errors.Error] =
  ## Decode array ``inbytes`` using MultiBase encoding and store decoded value
  ## to ``outbytes``.
  ##
  ## On success procedure returns number of bytes stored in ``outbytes`` array.
  let length = len(inbytes)
  if length == 0:
    result.err(errors.IncorrectEncodingError)
    return
  let mb = CodeMultibases.getOrDefault(inbytes[0])
  if len(mb.name) == 0:
    # This can be different error, if list of supported codecs will be stable.
    result.err(errors.NoSupportError)
    return
  if isNil(mb.decr) or isNil(mb.decl):
    result.err(errors.NoSupportError)
    return

  if length == 1:
    result.ok(0)
  else:
    result = mb.decr(inbytes.toOpenArray(1, length - 1), outbytes)

proc encode*(mbtype: typedesc[MultiBase], encoding: string,
             inbytes: openarray[byte]): Result[string, errors.Error] =
  ## Encode array ``inbytes`` using MultiBase encoding scheme ``encoding`` and
  ## return encoded string.
  let length = len(inbytes)
  let mb = NameMultibases.getOrDefault(encoding)
  if len(mb.name) == 0:
    # This can be different error, if list of supported codecs will be stable.
    result.err(errors.NoSupportError)
    return
  if isNil(mb.encr) or isNil(mb.encl):
    result.err(errors.NoSupportError)
    return

  var buffer: string
  if length > 0:
    buffer = newString(mb.encl(length) + 1)
    let res = mb.encr(inbytes, buffer.toOpenArray(1, len(buffer) - 1))
    if res.isOk:
      buffer.setLen(res.value + 1)
      buffer[0] = mb.code
      result.ok(buffer)
    else:
      result.err(errors.IncorrectEncodingError)
  else:
    buffer = newString(1)
    buffer[0] = mb.code
    result.ok(buffer)

proc encode*(encoding: MultiBase, inbytes: openarray[byte]): string =
  ## Encode array ``inbytes`` using MultiBase encoding scheme ``encoding`` and
  ## return encoded string.
  let length = len(inbytes)
  let mb = BaseMultibases.getOrDefault(encoding)
  if length > 0:
    result = newString(encodedLength(encoding, length))
    let res = mb.encr(inbytes, result.toOpenArray(1, len(result) - 1))
    result.setLen(res.value + 1)
    result[0] = mb.code
  else:
    result = newString(1)
    result[0] = mb.code

proc decode*(mbtype: typedesc[MultiBase],
             inbytes: openarray[char]): Result[seq[byte], errors.Error] =
  ## Decode MultiBase encoded array ``inbytes`` and return decoded sequence of
  ## bytes.
  let length = len(inbytes)
  if length == 0:
    result.err(errors.IncorrectEncodingError)
    return
  let mb = CodeMultibases.getOrDefault(inbytes[0])
  if len(mb.name) == 0:
    result.err(errors.NoSupportError)
    return
  if isNil(mb.decr) or isNil(mb.decl):
    result.err(errors.NoSupportError)
    return

  if length == 1:
    var buffer = newSeq[byte]()
    result.ok(buffer)
  else:
    var buffer = newSeq[byte](mb.decl(length - 1))
    let res = mb.decr(inbytes.toOpenArray(1, length - 1), buffer)
    if res.isOk:
      buffer.setLen(res.value)
      result.ok(buffer)
    else:
      result.err(errors.IncorrectEncodingError)
