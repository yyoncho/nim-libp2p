## Nim-Libp2p
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

## This module implements constant-time ECDSA and ECDHE for NIST elliptic
## curves secp256r1, secp384r1 and secp521r1.
##
## This module uses unmodified parts of code from
## BearSSL library <https://bearssl.org/>
## Copyright(C) 2018 Thomas Pornin <pornin@bolet.org>.
import nimcrypto/utils
import common, minasn1, ../errors
export errors

const
  PubKey256Length* = 65
  PubKey384Length* = 97
  PubKey521Length* = 133
  SecKey256Length* = 32
  SecKey384Length* = 48
  SecKey521Length* = 66
  Sig256Length* = 64
  Sig384Length* = 96
  Sig521Length* = 132
  Secret256Length* = SecKey256Length
  Secret384Length* = SecKey384Length
  Secret521Length* = SecKey521Length

type
  EcPrivateKey* = ref object
    buffer*: seq[byte]
    key*: BrEcPrivateKey

  EcPublicKey* = ref object
    buffer*: seq[byte]
    key*: BrEcPublicKey

  EcKeyPair* = object
    seckey*: EcPrivateKey
    pubkey*: EcPublicKey

  EcSignature* = ref object
    buffer*: seq[byte]

  EcCurveKind* = enum
    Secp256r1 = BR_EC_SECP256R1,
    Secp384r1 = BR_EC_SECP384R1,
    Secp521r1 = BR_EC_SECP521R1

  EcPKI* = EcPrivateKey | EcPublicKey | EcSignature

const
  EcSupportedCurvesCint* = {cint(Secp256r1), cint(Secp384r1), cint(Secp521r1)}

proc `-`(x: uint32): uint32 {.inline.} =
  result = (0xFFFF_FFFF'u32 - x) + 1'u32

proc GT(x, y: uint32): uint32 {.inline.} =
  var z = cast[uint32](y - x)
  result = (z xor ((x xor y) and (x xor z))) shr 31

proc CMP(x, y: uint32): int32 {.inline.} =
  cast[int32](GT(x, y)) or -(cast[int32](GT(y, x)))

proc EQ0(x: int32): uint32 {.inline.} =
  var q = cast[uint32](x)
  result = not(q or -q) shr 31

proc NEQ(x, y: uint32): uint32 {.inline.} =
  var q = cast[uint32](x xor y)
  result = ((q or -q) shr 31)

proc LT0(x: int32): uint32 {.inline.} =
  result = cast[uint32](x) shr 31

proc checkScalar(scalar: openarray[byte], curve: cint): uint32 =
  ## Return ``1`` if all of the following hold:
  ##   - len(``scalar``) <= ``orderlen``
  ##   - ``scalar`` != 0
  ##   - ``scalar`` is lower than the curve ``order``.
  ##
  ## Otherwise, return ``0``.
  var impl = brEcGetDefault()
  var orderlen = 0
  var order = cast[ptr UncheckedArray[byte]](impl.order(curve, addr orderlen))

  var z = 0'u32
  var c = 0'i32
  for u in scalar:
    z = z or u
  if len(scalar) == orderlen:
    for i in 0..<len(scalar):
      c = c or (-(cast[int32](EQ0(c))) and CMP(scalar[i], order[i]))
  else:
    c = -1
  result = NEQ(z, 0'u32) and LT0(c)

proc checkPublic(key: openarray[byte], curve: cint): uint32 =
  ## Return ``1`` if public key ``key`` is on curve.
  var ckey = @key
  var x = [0x00'u8, 0x01'u8]
  var impl = brEcGetDefault()
  var orderlen = 0
  var order = impl.order(curve, addr orderlen)
  result = impl.mul(cast[ptr cuchar](unsafeAddr ckey[0]), len(ckey),
                    cast[ptr cuchar](addr x[0]), len(x), curve)

proc getOffset(pubkey: EcPublicKey): int {.inline.} =
  let o = cast[uint](pubkey.key.q) - cast[uint](unsafeAddr pubkey.buffer[0])
  if o + cast[uint](pubkey.key.qlen) > uint(len(pubkey.buffer)):
    result = -1
  else:
    result = cast[int](o)

proc getOffset(seckey: EcPrivateKey): int {.inline.} =
  let o = cast[uint](seckey.key.x) - cast[uint](unsafeAddr seckey.buffer[0])
  if o + cast[uint](seckey.key.xlen) > uint(len(seckey.buffer)):
    result = -1
  else:
    result = cast[int](o)

template getPublicKeyLength*(curve: EcCurveKind): int =
  case curve
  of Secp256r1:
    PubKey256Length
  of Secp384r1:
    PubKey384Length
  of Secp521r1:
    PubKey521Length

proc copy*[T: EcPKI](dst: var T, src: T): bool =
  ## Copy EC `private key`, `public key` or `signature` ``src`` to ``dst``.
  ##
  ## Returns ``true`` on success, ``false`` otherwise.
  dst = new T
  when T is EcPrivateKey:
    let length = src.key.xlen
    if length > 0 and len(src.buffer) > 0:
      let offset = getOffset(src)
      if offset >= 0:
        dst.buffer = src.buffer
        dst.key.curve = src.key.curve
        dst.key.xlen = length
        dst.key.x = cast[ptr cuchar](addr dst.buffer[offset])
        result = true
  elif T is EcPublicKey:
    let length = src.key.qlen
    if length > 0 and len(src.buffer) > 0:
      let offset = getOffset(src)
      if offset >= 0:
        dst.buffer = src.buffer
        dst.key.curve = src.key.curve
        dst.key.qlen = length
        dst.key.q = cast[ptr cuchar](addr dst.buffer[offset])
        result = true
  else:
    let length = len(src.buffer)
    if length > 0:
      dst.buffer = src.buffer
      result = true

proc copy*[T: EcPKI](src: T): Result[T, errors.Error] {.inline.} =
  ## Returns copy of EC `private key`, `public key` or `signature`
  ## object ``src``.
  var res: T
  if not copy(res, src):
    result.err(errors.EcNistIncorrectError)
  else:
    result.ok(res)

proc clear*[T: EcPKI|EcKeyPair](pki: var T) =
  ## Wipe and clear EC `private key`, `public key` or `signature` object.
  when T is EcPrivateKey:
    burnMem(pki.buffer)
    pki.buffer.setLen(0)
    pki.key.x = nil
    pki.key.xlen = 0
    pki.key.curve = 0
  elif T is EcPublicKey:
    burnMem(pki.buffer)
    pki.buffer.setLen(0)
    pki.key.q = nil
    pki.key.qlen = 0
    pki.key.curve = 0
  elif T is EcSignature:
    burnMem(pki.buffer)
    pki.buffer.setLen(0)
  else:
    burnMem(pki.seckey.buffer)
    burnMem(pki.pubkey.buffer)
    pki.seckey.buffer.setLen(0)
    pki.pubkey.buffer.setLen(0)
    pki.seckey.key.x = nil
    pki.seckey.key.xlen = 0
    pki.seckey.key.curve = 0
    pki.pubkey.key.q = nil
    pki.pubkey.key.qlen = 0
    pki.pubkey.key.curve = 0

proc random*(t: typedesc[EcPrivateKey],
             kind: EcCurveKind): Result[EcPrivateKey, errors.Error] =
  ## Generate new random EC private key using BearSSL's HMAC-SHA256-DRBG
  ## algorithm.
  ##
  ## ``kind`` elliptic curve kind of your choice (secp256r1, secp384r1 or
  ## secp521r1).
  var rng: BrHmacDrbgContext
  var seeder = brPrngSeederSystem(nil)
  brHmacDrbgInit(addr rng, addr sha256Vtable, nil, 0)
  if seeder(addr rng.vtable) == 0:
    result.err(errors.RandomGeneratorError)
    return
  var ecimp = brEcGetDefault()
  var key = new EcPrivateKey
  key.buffer = newSeq[byte](BR_EC_KBUF_PRIV_MAX_SIZE)
  if brEcKeygen(addr rng.vtable, ecimp,
                addr key.key, addr key.buffer[0],
                cast[cint](kind)) == 0:
    result.err(errors.EcNistKeyGenerationError)
  else:
    result.ok(key)

proc getKey*(seckey: EcPrivateKey): EcPublicKey =
  ## Calculate and return EC public key from private key ``seckey``.
  var ecimp = brEcGetDefault()
  let length = getPublicKeyLength(cast[EcCurveKind](seckey.key.curve))
  result = new EcPublicKey
  result.buffer = newSeq[byte](length)
  discard brEcComputePublicKey(ecimp, addr result.key,
                               addr result.buffer[0], unsafeAddr seckey.key)

proc random*(t: typedesc[EcKeyPair],
             kind: EcCurveKind): Result[EcKeyPair, errors.Error] {.inline.} =
  ## Generate new random EC private and public keypair using BearSSL's
  ## HMAC-SHA256-DRBG algorithm.
  ##
  ## ``kind`` elliptic curve kind of your choice (secp256r1, secp384r1 or
  ## secp521r1).
  var seckey = EcPrivateKey.random(kind)
  if seckey.isErr:
    result.err(seckey.error)
    return
  var pubkey = seckey.value.getKey()
  result.ok(EcKeyPair(seckey: seckey.value, pubkey: pubkey))

proc `$`*(seckey: EcPrivateKey): string =
  ## Return string representation of EC private key.
  if seckey.key.curve == 0 or seckey.key.xlen == 0 or len(seckey.buffer) == 0:
    result = "Empty key"
  else:
    if seckey.key.curve notin EcSupportedCurvesCint:
      result = "Unknown key"
    else:
      let offset = seckey.getOffset()
      if offset < 0:
        result = "Corrupted key"
      else:
        let e = offset + cast[int](seckey.key.xlen) - 1
        result = toHex(seckey.buffer.toOpenArray(offset, e))

proc `$`*(pubkey: EcPublicKey): string =
  ## Return string representation of EC public key.
  if pubkey.key.curve == 0 or pubkey.key.qlen == 0 or len(pubkey.buffer) == 0:
    result = "Empty key"
  else:
    if pubkey.key.curve notin EcSupportedCurvesCint:
      result = "Unknown key"
    else:
      let offset = pubkey.getOffset()
      if offset < 0:
        result = "Corrupted key"
      else:
        let e = offset + cast[int](pubkey.key.qlen) - 1
        result = toHex(pubkey.buffer.toOpenArray(offset, e))

proc `$`*(sig: EcSignature): string =
  ## Return hexadecimal string representation of EC signature.
  result = toHex(sig.buffer)

proc toBytes*(seckey: EcPrivateKey, data: var openarray[byte]): int =
  ## Serialize EC private key ``seckey`` to ASN.1 DER binary form and store it
  ## to ``data``.
  ##
  ## Procedure returns number of bytes (octets) needed to store EC private key,
  ## or `0` if private key is not in supported curve.
  if seckey.key.curve in EcSupportedCurvesCint:
    var offset, length: int
    var pubkey = seckey.getKey()
    var b = Asn1Buffer.init()
    var p = Asn1Composite.init(Asn1Tag.Sequence)
    var c0 = Asn1Composite.init(0)
    var c1 = Asn1Composite.init(1)
    if seckey.key.curve == BR_EC_SECP256R1:
      c0.write(Asn1Tag.Oid, Asn1OidSecp256r1)
    elif seckey.key.curve == BR_EC_SECP384R1:
      c0.write(Asn1Tag.Oid, Asn1OidSecp384r1)
    elif seckey.key.curve == BR_EC_SECP521R1:
      c0.write(Asn1Tag.Oid, Asn1OidSecp521r1)
    c0.finish()
    offset = pubkey.getOffset()
    length = pubkey.key.qlen
    c1.write(Asn1Tag.BitString,
             pubkey.buffer.toOpenArray(offset, offset + length - 1))
    c1.finish()
    offset = seckey.getOffset()
    length = seckey.key.xlen
    p.write(1'u64)
    p.write(Asn1Tag.OctetString,
            seckey.buffer.toOpenArray(offset, offset + length - 1))
    p.write(c0)
    p.write(c1)
    p.finish()
    b.write(p)
    b.finish()
    result = len(b)
    if len(data) >= result:
      copyMem(addr data[0], addr b.buffer[0], result)

proc toBytes*(pubkey: EcPublicKey, data: var openarray[byte]): int =
  ## Serialize EC public key ``pubkey`` to ASN.1 DER binary form and store it
  ## to ``data``.
  ##
  ## Procedure returns number of bytes (octets) needed to store EC public key,
  ## or `0` if public key is not in supported curve.
  if pubkey.key.curve in EcSupportedCurvesCint:
    var b = Asn1Buffer.init()
    var p = Asn1Composite.init(Asn1Tag.Sequence)
    var c = Asn1Composite.init(Asn1Tag.Sequence)
    c.write(Asn1Tag.Oid, Asn1OidEcPublicKey)
    if pubkey.key.curve == BR_EC_SECP256R1:
      c.write(Asn1Tag.Oid, Asn1OidSecp256r1)
    elif pubkey.key.curve == BR_EC_SECP384R1:
      c.write(Asn1Tag.Oid, Asn1OidSecp384r1)
    elif pubkey.key.curve == BR_EC_SECP521R1:
      c.write(Asn1Tag.Oid, Asn1OidSecp521r1)
    c.finish()
    p.write(c)
    let offset = getOffset(pubkey)
    let length = pubkey.key.qlen
    p.write(Asn1Tag.BitString,
            pubkey.buffer.toOpenArray(offset, offset + length - 1))
    p.finish()
    b.write(p)
    b.finish()
    result = len(b)
    if len(data) >= result:
      copyMem(addr data[0], addr b.buffer[0], result)

proc toBytes*(sig: EcSignature, data: var openarray[byte]): int =
  ## Serialize EC signature ``sig`` to ASN.1 DER binary form and store it
  ## to ``data``.
  ##
  ## Procedure returns number of bytes (octets) needed to store EC signature,
  ## or `0` if signature is not in supported curve.
  result = len(sig.buffer)
  if len(data) >= result:
    copyMem(addr data[0], unsafeAddr sig.buffer[0], result)

proc getBytes*(seckey: EcPrivateKey): seq[byte] =
  ## Serialize EC private key ``seckey`` to ASN.1 DER binary form and return it.
  if seckey.key.curve in EcSupportedCurvesCint:
    result = newSeq[byte]()
    let length = seckey.toBytes(result)
    result.setLen(length)
    discard seckey.toBytes(result)

proc getBytes*(pubkey: EcPublicKey): seq[byte] =
  ## Serialize EC public key ``pubkey`` to ASN.1 DER binary form and return it.
  if pubkey.key.curve in EcSupportedCurvesCint:
    result = newSeq[byte]()
    let length = pubkey.toBytes(result)
    result.setLen(length)
    discard pubkey.toBytes(result)

proc getBytes*(sig: EcSignature): seq[byte] =
  ## Serialize EC signature ``sig`` to ASN.1 DER binary form and return it.
  result = newSeq[byte]()
  let length = sig.toBytes(result)
  result.setLen(length)
  discard sig.toBytes(result)

proc `==`*(pubkey1, pubkey2: EcPublicKey): bool =
  ## Returns ``true`` if both keys ``pubkey1`` and ``pubkey2`` are equal.
  if pubkey1.key.curve != pubkey2.key.curve:
    return false
  if pubkey1.key.qlen != pubkey2.key.qlen:
    return false
  let op1 = pubkey1.getOffset()
  let op2 = pubkey2.getOffset()
  if op1 == -1 or op2 == -1:
    return false
  result = equalMem(unsafeAddr pubkey1.buffer[op1],
                    unsafeAddr pubkey2.buffer[op2], pubkey1.key.qlen)

proc `==`*(seckey1, seckey2: EcPrivateKey): bool =
  ## Returns ``true`` if both keys ``seckey1`` and ``seckey2`` are equal.
  if seckey1.key.curve != seckey2.key.curve:
    return false
  if seckey1.key.xlen != seckey2.key.xlen:
    return false
  let op1 = seckey1.getOffset()
  let op2 = seckey2.getOffset()
  if op1 == -1 or op2 == -1:
    return false
  result = equalMem(unsafeAddr seckey1.buffer[op1],
                    unsafeAddr seckey2.buffer[op2], seckey1.key.xlen)

proc `==`*(sig1, sig2: EcSignature): bool =
  ## Return ``true`` if both signatures ``sig1`` and ``sig2`` are equal.
  result = (sig1.buffer == sig2.buffer)

proc init*(tkey: typedesc[EcPrivateKey],
           data: openarray[byte]): Result[EcPrivateKey, errors.Error] =
  ## Initialize EC `private key` or `signature` ``key`` from ASN.1 DER binary
  ## representation ``data``.
  var curve: cint

  var ab = Asn1Buffer.init(data)

  var field = ab.read()
  if field.isErr:
    result.err(field.error)
    return
  if field.value.kind != Asn1Tag.Sequence:
    result.err(errors.EcNistIncorrectBinaryFormError)
    return

  var ib = field.value.getBuffer()

  field = ib.read()
  if field.isErr:
    result.err(field.error)
    return
  if field.value.kind != Asn1Tag.Integer:
    result.err(errors.EcNistIncorrectBinaryFormError)
    return
  if field.value.vint != 1'u64:
    result.err(errors.EcNistIncorrectBinaryFormError)
    return

  var raw = ib.read()
  if raw.isErr:
    result.err(raw.error)
    return
  if raw.value.kind != Asn1Tag.OctetString:
    result.err(errors.EcNistIncorrectBinaryFormError)
    return

  var oid = ib.read()
  if oid.isErr:
    result.err(oid.error)
    return
  if oid.value.kind != Asn1Tag.Oid:
    result.err(errors.EcNistIncorrectBinaryFormError)
    return

  if oid.value == Asn1OidSecp256r1:
    curve = cast[cint](Secp256r1)
  elif oid.value == Asn1OidSecp384r1:
    curve = cast[cint](Secp384r1)
  elif oid.value == Asn1OidSecp521r1:
    curve = cast[cint](Secp521r1)
  else:
    result.err(errors.EcNistCurveNoSupportError)
    return

  if checkScalar(raw.value.toOpenArray(), curve) == 1'u32:
    var key = new EcPrivateKey
    key.buffer = newSeq[byte](raw.value.length)
    copyMem(addr key.buffer[0], addr raw.value.buffer[raw.value.offset],
            raw.value.length)
    key.key.x = cast[ptr cuchar](addr key.buffer[0])
    key.key.xlen = raw.value.length
    key.key.curve = curve
    result.ok(key)
  else:
    result.err(errors.EcNistIncorrectBinaryFormError)
    return

proc init*(tkey: typedesc[EcPublicKey],
           data: openarray[byte]): Result[EcPublicKey, errors.Error] =
  ## Initialize EC public key ``pubkey`` from ASN.1 DER binary representation
  ## ``data``.
  var curve: cint

  var ab = Asn1Buffer.init(data)

  var field = ab.read()
  if field.isErr:
    result.err(field.error)
    return
  if field.value.kind != Asn1Tag.Sequence:
    result.err(errors.EcNistIncorrectBinaryFormError)
    return

  var ib = field.value.getBuffer()

  field = ib.read()
  if field.isErr:
    result.err(field.error)
    return
  if field.value.kind != Asn1Tag.Sequence:
    result.err(errors.EcNistIncorrectBinaryFormError)
    return

  var ob = field.value.getBuffer()

  var oid = ob.read()
  if oid.isErr:
    result.err(oid.error)
    return
  if oid.value.kind != Asn1Tag.Oid:
    result.err(errors.EcNistIncorrectBinaryFormError)
    return
  if not(`==`(oid.value, Asn1OidEcPublicKey)):
    result.err(errors.EcNistIncorrectBinaryFormError)
    return

  oid = ob.read()
  if oid.isErr:
    result.err(oid.error)
    return
  if oid.value.kind != Asn1Tag.Oid:
    result.err(errors.EcNistIncorrectBinaryFormError)
    return

  if oid.value == Asn1OidSecp256r1:
    curve = cast[cint](Secp256r1)
  elif oid.value == Asn1OidSecp384r1:
    curve = cast[cint](Secp384r1)
  elif oid.value == Asn1OidSecp521r1:
    curve = cast[cint](Secp521r1)
  else:
    result.err(errors.EcNistCurveNoSupportError)
    return

  var raw = ib.read()
  if raw.isErr:
    result.err(raw.error)
    return
  if raw.value.kind != Asn1Tag.BitString:
    result.err(errors.EcNistIncorrectBinaryFormError)
    return

  if checkPublic(raw.value.toOpenArray(), curve) != 0:
    var key = new EcPublicKey
    key.buffer = newSeq[byte](raw.value.length)
    copyMem(addr key.buffer[0], addr raw.value.buffer[raw.value.offset],
            raw.value.length)
    key.key.q = cast[ptr cuchar](addr key.buffer[0])
    key.key.qlen = raw.value.length
    key.key.curve = curve
    result.ok(key)
  else:
    result.err(errors.EcNistIncorrectBinaryFormError)

proc init*(tsig: typedesc[EcSignature],
           data: openarray[byte]): Result[EcSignature, errors.Error] =
  ## Initialize EC signature ``sig`` from raw binary representation ``data``.
  if len(data) > 0:
    var sig = new EcSignature
    sig.buffer = @data
    result.ok(sig)
  else:
    result.err(EcNistIncorrectBinaryFormError)

proc init*(t: typedesc[EcPrivateKey],
           data: string): Result[EcPrivateKey, errors.Error] =
  ## Initialize EC `private key` from ASN.1 DER hexadecimal string
  ## representation ``data``.
  var buffer: seq[byte]
  try:
    buffer = fromHex(data)
  except:
    result.err(IncorrectHexadecimalError)
    return
  result = t.init(buffer)

proc init*(t: typedesc[EcPublicKey],
           data: string): Result[EcPublicKey, errors.Error] =
  ## Initialize EC `public key` from ASN.1 DER hexadecimal string
  ## representation ``data``.
  var buffer: seq[byte]
  try:
    buffer = fromHex(data)
  except:
    result.err(IncorrectHexadecimalError)
    return
  result = t.init(buffer)

proc init*(t: typedesc[EcSignature],
           data: string): Result[EcSignature, errors.Error] =
  ## Initialize EC `signature` from raw hexadecimal string
  ## representation ``data``.
  var buffer: seq[byte]
  try:
    buffer = fromHex(data)
  except:
    result.err(IncorrectHexadecimalError)
    return
  result = t.init(buffer)

proc initRaw*(t: typedesc[EcPrivateKey],
              data: openarray[byte]): Result[EcPrivateKey, errors.Error] =
  ## Initialize EC `private key` or `scalar` ``key`` from raw binary
  ## representation ``data``.
  ##
  ## Length of ``data`` array must be ``SecKey256Length``, ``SecKey384Length``
  ## or ``SecKey521Length``.
  var curve: cint

  if len(data) == SecKey256Length:
    curve = cast[cint](Secp256r1)
  elif len(data) == SecKey384Length:
    curve = cast[cint](Secp384r1)
  elif len(data) == SecKey521Length:
    curve = cast[cint](Secp521r1)
  else:
    result.err(EcNistCurveNoSupportError)
    return

  if checkScalar(data, curve) == 1'u32:
    let length = len(data)
    var key = new EcPrivateKey
    key.buffer = newSeq[byte](length)
    copyMem(addr key.buffer[0], unsafeAddr data[0], length)
    key.key.x = cast[ptr cuchar](addr key.buffer[0])
    key.key.xlen = length
    key.key.curve = curve
    result.ok(key)
  else:
    result.err(EcNistIncorrectBinaryFormError)

proc initRaw*(t: typedesc[EcPublicKey],
              data: openarray[byte]): Result[EcPublicKey, errors.Error] =
  ## Initialize EC public key ``pubkey`` from raw binary representation
  ## ``data``.
  ##
  ## Length of ``data`` array must be ``PubKey256Length``, ``PubKey384Length``
  ## or ``PubKey521Length``.
  var curve: cint
  if len(data) == 0:
    result.err(EcNistIncorrectBinaryFormError)
    return

  if data[0] != 0x04'u8:
    result.err(EcNistIncorrectBinaryFormError)
    return

  if len(data) == PubKey256Length:
    curve = cast[cint](Secp256r1)
  elif len(data) == PubKey384Length:
    curve = cast[cint](Secp384r1)
  elif len(data) == PubKey521Length:
    curve = cast[cint](Secp521r1)
  else:
    result.err(EcNistIncorrectBinaryFormError)
    return

  if checkPublic(data, curve) != 0:
    let length = len(data)
    var key = new EcPublicKey
    key.buffer = newSeq[byte](length)
    copyMem(addr key.buffer[0], unsafeAddr data[0], length)
    key.key.q = cast[ptr cuchar](addr key.buffer[0])
    key.key.qlen = length
    key.key.curve = curve
    result.ok(key)
  else:
    result.err(EcNistIncorrectBinaryFormError)

proc initRaw*(t: typedesc[EcSignature],
              data: openarray[byte]): Result[EcSignature, errors.Error] =
  ## Initialize EC signature ``sig`` from raw binary representation ``data``.
  ##
  ## Length of ``data`` array must be ``Sig256Length``, ``Sig384Length``
  ## or ``Sig521Length``.
  var curve: cint
  let length = len(data)
  if (length == Sig256Length) or (length == Sig384Length) or
     (length == Sig521Length):
    var sig = new EcSignature
    sig.buffer = @data
    result.ok(sig)
  else:
    result.err(EcNistIncorrectBinaryFormError)

proc initRaw*(t: typedesc[EcPrivateKey],
              data: string): Result[EcPrivateKey, errors.Error] =
  ## Initialize EC `signature` from raw hexadecimal string
  ## representation ``data``.
  var buffer: seq[byte]
  try:
    buffer = fromHex(data)
  except:
    result.err(IncorrectHexadecimalError)
    return
  result = t.initRaw(buffer)

proc initRaw*(t: typedesc[EcPublicKey],
              data: string): Result[EcPublicKey, errors.Error] =
  ## Initialize EC `signature` from raw hexadecimal string
  ## representation ``data``.
  var buffer: seq[byte]
  try:
    buffer = fromHex(data)
  except:
    result.err(IncorrectHexadecimalError)
    return
  result = t.initRaw(buffer)

proc initRaw*(t: typedesc[EcSignature],
           data: string): Result[EcSignature, errors.Error] =
  ## Initialize EC `signature` from raw hexadecimal string
  ## representation ``data``.
  var buffer: seq[byte]
  try:
    buffer = fromHex(data)
  except:
    result.err(IncorrectHexadecimalError)
    return
  result = t.initRaw(buffer)

proc scalarMul*(pub: EcPublicKey,
                sec: EcPrivateKey): Result[EcPublicKey, errors.Error] =
  ## Return scalar multiplication of ``pub`` and ``sec``.
  ##
  ## Returns point in curve as ``pub * sec`` or ``nil`` otherwise.
  var impl = brEcGetDefault()
  if sec.key.curve notin EcSupportedCurvesCint:
    result.err(EcNistCurveNoSupportError)
    return
  if pub.key.curve != sec.key.curve:
    result.err(EcNistDifferentCurvesError)
    return

  var key = new EcPublicKey
  if not key.copy(pub):
    result.err(EcNistKeyComputationError)
    return

  var slength = cint(0)
  let poffset = key.getOffset()
  let soffset = sec.getOffset()
  if poffset < 0 or soffset < 0:
    result.err(EcNistKeyComputationError)
    return

  let res = impl.mul(cast[ptr cuchar](addr key.buffer[poffset]),
                     key.key.qlen,
                     cast[ptr cuchar](unsafeAddr sec.buffer[soffset]),
                     sec.key.xlen,
                     key.key.curve)
  if res == 0:
    result.err(EcNistMultiplicationError)
  else:
    result.ok(key)

proc getSecret*(pubkey: EcPublicKey,
                seckey: EcPrivateKey): Result[seq[byte], errors.Error] =
  ## Calculate ECDHE shared secret using Go's elliptic curve approach, using
  ## remote public key ``pubkey`` and local private key ``seckey`` and return
  ## shared secret as array of bytes.
  var mult = scalarMul(pubkey, seckey)
  if mult.isErr:
    result.err(mult.error)
    return

  var length = 0
  if seckey.key.curve == BR_EC_SECP256R1:
    length = Secret256Length
  elif seckey.key.curve == BR_EC_SECP384R1:
    length = Secret384Length
  elif seckey.key.curve == BR_EC_SECP521R1:
    length = Secret521Length
  else:
    result.err(errors.EcNistCurveNoSupportError)
    return

  var qplus1 = cast[pointer](cast[uint](mult.value.key.q) + 1'u)
  var data = newSeq[byte](length)
  copyMem(addr data[0], qplus1, length)
  result.ok(data)

proc sign*[T: byte|char](seckey: EcPrivateKey,
                         message: openarray[T]): EcSignature =
  ## Get ECDSA signature of data ``message`` using private key ``seckey``.
  var hc: BrHashCompatContext
  var hash: array[32, byte]
  var impl = brEcGetDefault()

  var sig = new EcSignature
  sig.buffer = newSeq[byte](256)
  var kv = addr sha256Vtable
  kv.init(addr hc.vtable)
  if len(message) > 0:
    kv.update(addr hc.vtable, unsafeAddr message[0], len(message))
  else:
    kv.update(addr hc.vtable, nil, 0)
  kv.output(addr hc.vtable, addr hash[0])
  let res = brEcdsaSignAsn1(impl, kv, addr hash[0], addr seckey.key,
                            addr sig.buffer[0])
  # Clear context with initial value
  kv.init(addr hc.vtable)
  # We ignore error here, because we supplied all the buffers and values
  # properly.
  sig.buffer.setLen(res)
  result = sig

proc verify*[T: byte|char](sig: EcSignature, message: openarray[T],
                           pubkey: EcPublicKey): bool {.inline.} =
  ## Verify ECDSA signature ``sig`` using public key ``pubkey`` and data
  ## ``message``.
  ##
  ## Return ``true`` if message verification succeeded, ``false`` if
  ## verification failed.
  var hc: BrHashCompatContext
  var hash: array[32, byte]
  var impl = brEcGetDefault()
  if pubkey.key.curve in EcSupportedCurvesCint:
    var kv = addr sha256Vtable
    kv.init(addr hc.vtable)
    if len(message) > 0:
      kv.update(addr hc.vtable, unsafeAddr message[0], len(message))
    else:
      kv.update(addr hc.vtable, nil, 0)
    kv.output(addr hc.vtable, addr hash[0])
    let res = brEcdsaVerifyAsn1(impl, addr hash[0], len(hash),
                                unsafeAddr pubkey.key,
                                addr sig.buffer[0], len(sig.buffer))
    # Clear context with initial value
    kv.init(addr hc.vtable)
    result = (res == 1)
