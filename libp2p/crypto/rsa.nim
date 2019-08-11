## Nim-Libp2p
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

## This module implements constant-time RSA PKCS#1.5 DSA.
##
## This module uses unmodified parts of code from
## BearSSL library <https://bearssl.org/>
## Copyright(C) 2018 Thomas Pornin <pornin@bolet.org>.

import nimcrypto/utils
import common, minasn1, ../errors
export errors

const
  DefaultPublicExponent* = 3'u32
    ## Default value for RSA public exponent.
  MinKeySize* = 512
    ## Minimal allowed RSA key size in bits.
  DefaultKeySize* = 2048
    ## Default RSA key size in bits.

  RsaOidSha1* = [
    0x05'u8, 0x2B'u8, 0x0E'u8, 0x03'u8, 0x02'u8, 0x1A'u8
  ]
    ## RSA PKCS#1.5 SHA-1 hash object identifier.
  RsaOidSha224* = [
    0x09'u8, 0x60'u8, 0x86'u8, 0x48'u8, 0x01'u8, 0x65'u8, 0x03'u8, 0x04'u8,
    0x02'u8, 0x04'u8
  ]
    ## RSA PKCS#1.5 SHA-224 hash object identifier.
  RsaOidSha256* = [
    0x09'u8, 0x60'u8, 0x86'u8, 0x48'u8, 0x01'u8, 0x65'u8, 0x03'u8, 0x04'u8,
    0x02'u8, 0x01'u8
  ]
    ## RSA PKCS#1.5 SHA-256 hash object identifier.
  RsaOidSha384* = [
    0x09'u8, 0x60'u8, 0x86'u8, 0x48'u8, 0x01'u8, 0x65'u8, 0x03'u8, 0x04'u8,
    0x02'u8, 0x02'u8
  ]
    ## RSA PKCS#1.5 SHA-384 hash object identifier.
  RsaOidSha512* = [
    0x09'u8, 0x60'u8, 0x86'u8, 0x48'u8, 0x01'u8, 0x65'u8, 0x03'u8, 0x04'u8,
    0x02'u8, 0x03'u8
  ]
    ## RSA PKCS#1.5 SHA-512 hash object identifier.

type
  RsaPrivateKey* = ref object
    buffer*: seq[byte]
    seck*: BrRsaPrivateKey
    pubk*: BrRsaPublicKey
    pexp*: ptr cuchar
    pexplen*: int

  RsaPublicKey* = ref object
    buffer*: seq[byte]
    key*: BrRsaPublicKey

  RsaKeyPair* = RsaPrivateKey

  RsaSignature* = ref object
    buffer*: seq[byte]

  RsaPKI* = RsaPrivateKey | RsaPublicKey | RsaSignature
  RsaKeyOrPair* = RsaPrivateKey | RsaKeyPair

template getStart(bs, os, ls: untyped): untyped =
  let p = cast[uint](os)
  let s = cast[uint](unsafeAddr bs[0])
  var so = 0
  if p >= s:
    so = cast[int](p - s)
  so

template getFinish(bs, os, ls: untyped): untyped =
  let p = cast[uint](os)
  let s = cast[uint](unsafeAddr bs[0])
  var eo = -1
  if p >= s:
    let so = cast[int](p - s)
    if so + ls <= len(bs):
      eo = so + ls - 1
  eo

template getArray*(bs, os, ls: untyped): untyped =
  toOpenArray(bs, getStart(bs, os, ls), getFinish(bs, os, ls))

template trimZeroes(b: seq[byte], pt, ptlen: untyped) =
  var length = ptlen
  for i in 0..<length:
    if pt[] != cast[cuchar](0x00'u8):
      break
    pt = cast[ptr cuchar](cast[uint](pt) + 1)
    ptlen -= 1

proc random*[T: RsaKeyOrPair](t: typedesc[T], bits = DefaultKeySize,
                      pubexp = DefaultPublicExponent): Result[T, errors.Error] =
  ## Generate new random RSA private key using BearSSL's HMAC-SHA256-DRBG
  ## algorithm.
  ##
  ## ``bits`` number of bits in RSA key, must be in
  ## range [512, 4096] (default = 2048).
  ##
  ## ``pubexp`` is RSA public exponent, which must be prime (default = 3).
  var rng: BrHmacDrbgContext
  var keygen: BrRsaKeygen
  var seeder = brPrngSeederSystem(nil)
  var kp: T
  brHmacDrbgInit(addr rng, addr sha256Vtable, nil, 0)
  if seeder(addr rng.vtable) == 0:
    result.err(errors.RandomGeneratorError)
    return
  keygen = brRsaKeygenGetDefault()

  let length = brRsaPrivateKeyBufferSize(bits) +
               brRsaPublicKeyBufferSize(bits) +
               ((bits + 7) shr 3)
  let sko = 0
  let pko = brRsaPrivateKeyBufferSize(bits)
  let eko = pko + brRsaPublicKeyBufferSize(bits)

  when T is RsaKeyPair:
    kp = new RsaKeyPair
  else:
    kp = new RsaPrivateKey

  kp.buffer = newSeq[byte](length)
  if keygen(addr rng.vtable,
            addr kp.seck, addr kp.buffer[sko],
            addr kp.pubk, addr kp.buffer[pko],
            cuint(bits), pubexp) == 0:
    result.err(errors.RSAKeyGenerationError)
    return

  let compute = brRsaComputePrivexpGetDefault()
  let res = compute(addr kp.buffer[eko], addr kp.seck, pubexp)
  if res == 0:
    result.err(errors.RSAKeyComputationError)
    return

  kp.pexp = cast[ptr cuchar](addr kp.buffer[eko])
  kp.pexplen = res

  trimZeroes(kp.buffer, kp.seck.p, kp.seck.plen)
  trimZeroes(kp.buffer, kp.seck.q, kp.seck.qlen)
  trimZeroes(kp.buffer, kp.seck.dp, kp.seck.dplen)
  trimZeroes(kp.buffer, kp.seck.dq, kp.seck.dqlen)
  trimZeroes(kp.buffer, kp.seck.iq, kp.seck.iqlen)
  trimZeroes(kp.buffer, kp.pubk.n, kp.pubk.nlen)
  trimZeroes(kp.buffer, kp.pubk.e, kp.pubk.elen)
  trimZeroes(kp.buffer, kp.pexp, kp.pexplen)

  result.ok(kp)

proc copy*[T: RsaPKI](key: T): T =
  ## Create copy of RSA private key, public key or signature.
  when T is RsaPrivateKey:
    if len(key.buffer) > 0:
      let length = key.seck.plen + key.seck.qlen + key.seck.dplen +
                   key.seck.dqlen + key.seck.iqlen + key.pubk.nlen +
                   key.pubk.elen + key.pexplen
      result = new RsaPrivateKey
      result.buffer = newSeq[byte](length)
      let po = 0
      let qo = po + key.seck.plen
      let dpo = qo + key.seck.qlen
      let dqo = dpo + key.seck.dplen
      let iqo = dqo + key.seck.dqlen
      let no = iqo + key.seck.iqlen
      let eo = no + key.pubk.nlen
      let peo = eo + key.pubk.elen
      copyMem(addr result.buffer[po], key.seck.p, key.seck.plen)
      copyMem(addr result.buffer[qo], key.seck.q, key.seck.qlen)
      copyMem(addr result.buffer[dpo], key.seck.dp, key.seck.dplen)
      copyMem(addr result.buffer[dqo], key.seck.dq, key.seck.dqlen)
      copyMem(addr result.buffer[iqo], key.seck.iq, key.seck.iqlen)
      copyMem(addr result.buffer[no], key.pubk.n, key.pubk.nlen)
      copyMem(addr result.buffer[eo], key.pubk.e, key.pubk.elen)
      copyMem(addr result.buffer[peo], key.pexp, key.pexplen)
      result.seck.p = cast[ptr cuchar](addr result.buffer[po])
      result.seck.q = cast[ptr cuchar](addr result.buffer[qo])
      result.seck.dp = cast[ptr cuchar](addr result.buffer[dpo])
      result.seck.dq = cast[ptr cuchar](addr result.buffer[dqo])
      result.seck.iq = cast[ptr cuchar](addr result.buffer[iqo])
      result.pubk.n = cast[ptr cuchar](addr result.buffer[no])
      result.pubk.e = cast[ptr cuchar](addr result.buffer[eo])
      result.pexp = cast[ptr cuchar](addr result.buffer[peo])
      result.seck.plen = key.seck.plen
      result.seck.qlen = key.seck.qlen
      result.seck.dplen = key.seck.dplen
      result.seck.dqlen = key.seck.dqlen
      result.seck.iqlen = key.seck.iqlen
      result.pubk.nlen = key.pubk.nlen
      result.pubk.elen = key.pubk.elen
      result.pexplen = key.pexplen
      result.seck.nBitlen = key.seck.nBitlen
  elif T is RsaPublicKey:
    if len(key.buffer) > 0:
      let length = key.key.nlen + key.key.elen
      result = new RsaPublicKey
      result.buffer = newSeq[byte](length)
      let no = 0
      let eo = no + key.key.nlen
      copyMem(addr result.buffer[no], key.key.n, key.key.nlen)
      copyMem(addr result.buffer[eo], key.key.e, key.key.elen)
      result.key.n = cast[ptr cuchar](addr result.buffer[no])
      result.key.e = cast[ptr cuchar](addr result.buffer[eo])
      result.key.nlen = key.key.nlen
      result.key.elen = key.key.elen
  elif T is RsaSignature:
    if len(key.buffer) > 0:
      result = new RsaSignature
      result.buffer = key.buffer

proc getKey*(key: RsaPrivateKey): RsaPublicKey =
  ## Get RSA public key from RSA private key.
  let length = key.pubk.nlen + key.pubk.elen
  result = new RsaPublicKey
  result.buffer = newSeq[byte](length)
  result.key.n = cast[ptr cuchar](addr result.buffer[0])
  result.key.e = cast[ptr cuchar](addr result.buffer[key.pubk.nlen])
  copyMem(addr result.buffer[0], cast[pointer](key.pubk.n), key.pubk.nlen)
  copyMem(addr result.buffer[key.pubk.nlen], cast[pointer](key.pubk.e),
          key.pubk.elen)
  result.key.nlen = key.pubk.nlen
  result.key.elen = key.pubk.elen

proc seckey*(pair: RsaKeyPair): RsaPrivateKey {.inline.} =
  ## Get RSA private key from pair ``pair``.
  result = cast[RsaPrivateKey](pair).copy()

proc pubkey*(pair: RsaKeyPair): RsaPublicKey {.inline.} =
  ## Get RSA public key from pair ``pair``.
  result = cast[RsaPrivateKey](pair).getKey()

proc clear*[T: RsaPKI|RsaKeyPair](pki: var T) =
  ## Wipe and clear EC private key, public key or scalar object.
  when T is RsaPrivateKey:
    burnMem(pki.buffer)
    pki.buffer.setLen(0)
    pki.seckey.p = nil
    pki.seckey.q = nil
    pki.seckey.dp = nil
    pki.seckey.dq = nil
    pki.seckey.iq = nil
    pki.seckey.plen = 0
    pki.seckey.qlen = 0
    pki.seckey.dplen = 0
    pki.seckey.dqlen = 0
    pki.seckey.iqlen = 0
    pki.seckey.nBitlen = 0
    pki.pubkey.n = nil
    pki.pubkey.e = nil
    pki.pubkey.nlen = 0
    pki.pubkey.elen = 0
  elif T is RsaPublicKey:
    burnMem(pki.buffer)
    pki.buffer.setLen(0)
    pki.key.n = nil
    pki.key.e = nil
    pki.key.nlen = 0
    pki.key.elen = 0
  elif T is RsaSignature:
    burnMem(pki.buffer)
    pki.buffer.setLen(0)

proc toBytes*(key: RsaPrivateKey, data: var openarray[byte]): int =
  ## Serialize RSA private key ``key`` to ASN.1 DER binary form and store it
  ## to ``data``.
  ##
  ## Procedure returns number of bytes (octets) needed to store RSA private key,
  ## or `0` if private key is is incorrect.
  if len(key.buffer) > 0:
    var b = Asn1Buffer.init()
    var p = Asn1Composite.init(Asn1Tag.Sequence)
    p.write(0'u64)
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.pubk.n,
                                      key.pubk.nlen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.pubk.e,
                                      key.pubk.elen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.pexp, key.pexplen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.seck.p,
                                      key.seck.plen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.seck.q,
                                      key.seck.qlen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.seck.dp,
                                      key.seck.dplen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.seck.dq,
                                      key.seck.dqlen))
    p.write(Asn1Tag.Integer, getArray(key.buffer, key.seck.iq,
                                      key.seck.iqlen))
    p.finish()
    b.write(p)
    b.finish()
    result = len(b)
    if len(data) >= result:
      copyMem(addr data[0], addr b.buffer[0], result)

proc toBytes*(key: RsaPublicKey, data: var openarray[byte]): int =
  ## Serialize RSA public key ``key`` to ASN.1 DER binary form and store it
  ## to ``data``.
  ##
  ## Procedure returns number of bytes (octets) needed to store RSA public key,
  ## or `0` if public key is incorrect.
  if len(key.buffer) > 0:
    var b = Asn1Buffer.init()
    var p = Asn1Composite.init(Asn1Tag.Sequence)
    var c0 = Asn1Composite.init(Asn1Tag.Sequence)
    var c1 = Asn1Composite.init(Asn1Tag.BitString)
    var c10 = Asn1Composite.init(Asn1Tag.Sequence)
    c0.write(Asn1Tag.Oid, Asn1OidRsaEncryption)
    c0.write(Asn1Tag.Null)
    c0.finish()
    c10.write(Asn1Tag.Integer, getArray(key.buffer, key.key.n, key.key.nlen))
    c10.write(Asn1Tag.Integer, getArray(key.buffer, key.key.e, key.key.elen))
    c10.finish()
    c1.write(c10)
    c1.finish()
    p.write(c0)
    p.write(c1)
    p.finish()
    b.write(p)
    b.finish()
    result = len(b)
    if len(data) >= result:
      copyMem(addr data[0], addr b.buffer[0], result)

proc toBytes*(sig: RsaSignature, data: var openarray[byte]): int =
  ## Serialize RSA signature ``sig`` to raw binary form and store it
  ## to ``data``.
  ##
  ## Procedure returns number of bytes (octets) needed to store RSA public key,
  ## or `0` if public key is incorrect.
  result = len(sig.buffer)
  if len(data) >= result:
    copyMem(addr data[0], addr sig.buffer[0], result)

proc getBytes*(key: RsaPrivateKey): seq[byte] =
  ## Serialize RSA private key ``key`` to ASN.1 DER binary form and
  ## return it.
  result = newSeq[byte](8192)
  let length = key.toBytes(result)
  result.setLen(length)

proc getBytes*(key: RsaPublicKey): seq[byte] =
  ## Serialize RSA public key ``key`` to ASN.1 DER binary form and
  ## return it.
  result = newSeq[byte](8192)
  let length = key.toBytes(result)
  result.setLen(length)

proc getBytes*(sig: RsaSignature): seq[byte] =
  ## Serialize RSA signature ``sig`` to raw binary form and return it.
  result = newSeq[byte](8192)
  let length = sig.toBytes(result)
  result.setLen(length)

proc init*(tkey: typedesc[RsaPrivateKey],
           data: openarray[byte]): Result[RsaPrivateKey, errors.Error] =
  ## Initialize RSA private key ``key`` from ASN.1 DER binary representation
  ## ``data``.
  var ab = Asn1Buffer.init(data)

  let r0 = ab.read()
  if r0.isErr:
    result.err(r0.error)
    return
  if r0.value.kind != Asn1Tag.Sequence:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  var ib = r0.value.getBuffer()

  let r1 = ib.read()
  if r1.isErr:
    result.err(r1.error)
    return
  if r1.value.kind != Asn1Tag.Integer:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  if r1.value.vint != 0'u64:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  let rawn = ib.read()
  if rawn.isErr:
    result.err(rawn.error)
    return
  if rawn.value.kind != Asn1Tag.Integer:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  let rawpube = ib.read()
  if rawpube.isErr:
    result.err(rawpube.error)
    return
  if rawpube.value.kind != Asn1Tag.Integer:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  let rawprie = ib.read()
  if rawprie.isErr:
    result.err(rawprie.error)
    return
  if rawprie.value.kind != Asn1Tag.Integer:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  let rawp = ib.read()
  if rawp.isErr:
    result.err(rawp.error)
    return
  if rawp.value.kind != Asn1Tag.Integer:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  let rawq = ib.read()
  if rawq.isErr:
    result.err(rawq.error)
    return
  if rawq.value.kind != Asn1Tag.Integer:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  let rawdp = ib.read()
  if rawdp.isErr:
    result.err(rawdp.error)
    return
  if rawdp.value.kind != Asn1Tag.Integer:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  let rawdq = ib.read()
  if rawdq.isErr:
    result.err(rawdq.error)
    return
  if rawdq.value.kind != Asn1Tag.Integer:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  let rawiq = ib.read()
  if rawdq.isErr:
    result.err(rawiq.error)
    return
  if rawiq.value.kind != Asn1Tag.Integer:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  if len(rawn.value) < (MinKeySize shr 3):
    result.err(errors.RSAKeyTooSmallError)
    return

  if len(rawp.value) > 0 and len(rawq.value) > 0 and len(rawdp.value) > 0 and
     len(rawdq.value) > 0 and len(rawiq.value) > 0:
    var key = new RsaPrivateKey
    key.buffer = @data
    key.pubk.n = cast[ptr cuchar](addr key.buffer[rawn.value.offset])
    key.pubk.e = cast[ptr cuchar](addr key.buffer[rawpube.value.offset])
    key.seck.p = cast[ptr cuchar](addr key.buffer[rawp.value.offset])
    key.seck.q = cast[ptr cuchar](addr key.buffer[rawq.value.offset])
    key.seck.dp = cast[ptr cuchar](addr key.buffer[rawdp.value.offset])
    key.seck.dq = cast[ptr cuchar](addr key.buffer[rawdq.value.offset])
    key.seck.iq = cast[ptr cuchar](addr key.buffer[rawiq.value.offset])
    key.pexp = cast[ptr cuchar](addr key.buffer[rawprie.value.offset])
    key.pubk.nlen = len(rawn.value)
    key.pubk.elen = len(rawpube.value)
    key.seck.plen = len(rawp.value)
    key.seck.qlen = len(rawq.value)
    key.seck.dplen = len(rawdp.value)
    key.seck.dqlen = len(rawdq.value)
    key.seck.iqlen = len(rawiq.value)
    key.pexplen = len(rawprie.value)
    key.seck.nBitlen = cast[uint32](len(rawn.value) shl 3)
    result.ok(key)
  else:
    result.err(errors.RSAIncorrectBinaryFormError)

proc init*(tkey: typedesc[RsaPublicKey],
           data: openarray[byte]): Result[RsaPublicKey, errors.Error] =
  ## Initialize RSA public key ``key`` from ASN.1 DER binary representation
  ## ``data``.
  var ab = Asn1Buffer.init(data)

  var rfield = ab.read()
  if rfield.isErr:
    result.err(rfield.error)
    return
  if rfield.value.kind != Asn1Tag.Sequence:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  var ib = rfield.value.getBuffer()

  rfield = ib.read()
  if rfield.isErr:
    result.err(rfield.error)
    return
  if rfield.value.kind != Asn1Tag.Sequence:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  var ob = rfield.value.getBuffer()

  rfield = ob.read()
  if rfield.isErr:
    result.err(rfield.error)
    return
  if rfield.value.kind != Asn1Tag.Oid:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  if not(`==`(rfield.value, Asn1OidRsaEncryption)):
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  rfield = ob.read()
  if rfield.isErr:
    result.err(rfield.error)
    return
  if rfield.value.kind != Asn1Tag.Null:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  rfield = ib.read()
  if rfield.isErr:
    result.err(rfield.error)
    return
  if rfield.value.kind != Asn1Tag.BitString:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  var vb = rfield.value.getBuffer()

  rfield = vb.read()
  if rfield.isErr:
    result.err(rfield.error)
    return
  if rfield.value.kind != Asn1Tag.Sequence:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  var sb = rfield.value.getBuffer()

  var rawn = sb.read()
  if rawn.isErr:
    result.err(rawn.error)
    return
  if rawn.value.kind != Asn1Tag.Integer:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  var rawe = sb.read()
  if rawe.isErr:
    result.err(rawe.error)
    return
  if rawe.value.kind != Asn1Tag.Integer:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

  if len(rawn.value) < (MinKeySize shr 3):
    result.err(errors.RSAKeyTooSmallError)
    return

  if len(rawe.value) > 0:
    var key = new RsaPublicKey
    key.buffer = @data
    key.key.n = cast[ptr cuchar](addr key.buffer[rawn.value.offset])
    key.key.e = cast[ptr cuchar](addr key.buffer[rawe.value.offset])
    key.key.nlen = len(rawn.value)
    key.key.elen = len(rawe.value)
    result.ok(key)
  else:
    result.err(errors.RSAIncorrectBinaryFormError)

proc init*(tsig: typedesc[RsaSignature],
           data: openarray[byte]): Result[RsaSignature, errors.Error] =
  ## Initialize RSA signature ``sig`` from ASN.1 DER binary representation
  ## ``data``.
  if len(data) > 0:
    var sig = new RsaSignature
    sig.buffer = @data
    result.ok(sig)
  else:
    result.err(errors.RSAIncorrectBinaryFormError)
    return

proc init*(tkey: typedesc[RsaPrivateKey],
           data: string): Result[RsaPrivateKey, errors.Error] {.inline.} =
  ## Initialize RSA `private key` from hexadecimal string representation
  ## ``data``.
  var buffer: seq[byte]
  try:
    buffer = fromHex(data)
  except:
    result.err(errors.IncorrectHexadecimalError)
    return
  result = tkey.init(buffer)

proc init*(tkey: typedesc[RsaPublicKey],
           data: string): Result[RsaPublicKey, errors.Error] {.inline.} =
  ## Initialize RSA `public key` from hexadecimal string representation
  ## ``data``.
  var buffer: seq[byte]
  try:
    buffer = fromHex(data)
  except:
    result.err(errors.IncorrectHexadecimalError)
    return
  result = tkey.init(buffer)

proc init*(tsig: typedesc[RsaSignature],
           data: string): Result[RsaSignature, errors.Error] {.inline.} =
  ## Initialize RSA `signature` from hexadecimal string representation
  ## ``data``.
  var buffer: seq[byte]
  try:
    buffer = fromHex(data)
  except:
    result.err(errors.IncorrectHexadecimalError)
    return
  result = tsig.init(buffer)

proc `$`*(key: RsaPrivateKey): string =
  ## Return string representation of RSA private key.
  if len(key.buffer) == 0:
    result = "Empty RSA key"
  else:
    result = "RSA key ("
    result.add($key.seck.nBitlen)
    result.add(" bits)\n")
    result.add("p   = ")
    result.add(toHex(getArray(key.buffer, key.seck.p, key.seck.plen)))
    result.add("\nq   = ")
    result.add(toHex(getArray(key.buffer, key.seck.q, key.seck.qlen)))
    result.add("\ndp  = ")
    result.add(toHex(getArray(key.buffer, key.seck.dp, key.seck.dplen)))
    result.add("\ndq  = ")
    result.add(toHex(getArray(key.buffer, key.seck.dq, key.seck.dqlen)))
    result.add("\niq  = ")
    result.add(toHex(getArray(key.buffer, key.seck.iq, key.seck.iqlen)))
    result.add("\npre = ")
    result.add(toHex(getArray(key.buffer, key.pexp, key.pexplen)))
    result.add("\nm   = ")
    result.add(toHex(getArray(key.buffer, key.pubk.n, key.pubk.nlen)))
    result.add("\npue = ")
    result.add(toHex(getArray(key.buffer, key.pubk.e, key.pubk.elen)))
    result.add("\n")

proc `$`*(key: RsaPublicKey): string =
  ## Return string representation of RSA public key.
  if len(key.buffer) == 0:
    result = "Empty RSA key"
  else:
    let nbitlen = key.key.nlen shl 3
    result = "RSA key ("
    result.add($nbitlen)
    result.add(" bits)\nn = ")
    result.add(toHex(getArray(key.buffer, key.key.n, key.key.nlen)))
    result.add("\ne = ")
    result.add(toHex(getArray(key.buffer, key.key.e, key.key.elen)))
    result.add("\n")

proc `$`*(sig: RsaSignature): string =
  ## Return string representation of RSA signature.
  if len(sig.buffer) == 0:
    result = "Empty RSA signature"
  else:
    result = "RSA signature ("
    result.add(toHex(sig.buffer))
    result.add(")")

proc cmp(a: openarray[byte], b: openarray[byte]): bool =
  let alen = len(a)
  let blen = len(b)
  if alen == blen:
    if alen == 0:
      result = true
    else:
      var n = alen
      var res, diff: int
      while n > 0:
        dec(n)
        diff = int(a[n]) - int(b[n])
        res = (res and -not(diff)) or diff
      result = (res == 0)

proc `==`*(a, b: RsaPrivateKey): bool =
  ## Compare two RSA private keys for equality.
  if a.seck.nBitlen == b.seck.nBitlen:
    if cast[int](a.seck.nBitlen) > 0:
      let r1 = cmp(getArray(a.buffer, a.seck.p, a.seck.plen),
                   getArray(b.buffer, b.seck.p, b.seck.plen))
      let r2 = cmp(getArray(a.buffer, a.seck.q, a.seck.qlen),
                   getArray(b.buffer, b.seck.q, b.seck.qlen))
      let r3 = cmp(getArray(a.buffer, a.seck.dp, a.seck.dplen),
                   getArray(b.buffer, b.seck.dp, b.seck.dplen))
      let r4 = cmp(getArray(a.buffer, a.seck.dq, a.seck.dqlen),
                   getArray(b.buffer, b.seck.dq, b.seck.dqlen))
      let r5 = cmp(getArray(a.buffer, a.seck.iq, a.seck.iqlen),
                   getArray(b.buffer, b.seck.iq, b.seck.iqlen))
      let r6 = cmp(getArray(a.buffer, a.pexp, a.pexplen),
                   getArray(b.buffer, b.pexp, b.pexplen))
      let r7 = cmp(getArray(a.buffer, a.pubk.n, a.pubk.nlen),
                   getArray(b.buffer, b.pubk.n, b.pubk.nlen))
      let r8 = cmp(getArray(a.buffer, a.pubk.e, a.pubk.elen),
                   getArray(b.buffer, b.pubk.e, b.pubk.elen))
      result = r1 and r2 and r3 and r4 and r5 and r6 and r7 and r8
    else:
      result = true

proc `==`*(a, b: RsaSignature): bool =
  ## Compare two RSA signatures for equality.
  result = (a.buffer == b.buffer)

proc `==`*(a, b: RsaPublicKey): bool =
  ## Compare two RSA public keys for equality.
  let r1 = cmp(getArray(a.buffer, a.key.n, a.key.nlen),
               getArray(b.buffer, b.key.n, b.key.nlen))
  let r2 = cmp(getArray(a.buffer, a.key.e, a.key.elen),
               getArray(b.buffer, b.key.e, b.key.elen))
  result = r1 and r2

proc sign*[T: byte|char](key: RsaPrivateKey,
                         message: openarray[T]): RsaSignature =
  ## Get RSA PKCS1.5 signature of data ``message`` using SHA256 and private
  ## key ``key``.
  var hc: BrHashCompatContext
  var hash: array[32, byte]
  var impl = BrRsaPkcs1SignGetDefault()
  var sig = new RsaSignature
  sig.buffer = newSeq[byte]((key.seck.nBitlen + 7) shr 3)
  var kv = addr sha256Vtable
  kv.init(addr hc.vtable)
  if len(message) > 0:
    kv.update(addr hc.vtable, unsafeAddr message[0], len(message))
  else:
    kv.update(addr hc.vtable, nil, 0)
  kv.output(addr hc.vtable, addr hash[0])
  var oid = RsaOidSha256
  let res = impl(cast[ptr cuchar](addr oid[0]),
                 cast[ptr cuchar](addr hash[0]), len(hash),
                 addr key.seck, cast[ptr cuchar](addr sig.buffer[0]))
  # We ignore error here, because we supplied all the buffers and values
  # properly.
  result = sig

proc verify*[T: byte|char](sig: RsaSignature, message: openarray[T],
                           pubkey: RsaPublicKey): bool {.inline.} =
  ## Verify RSA signature ``sig`` using public key ``pubkey`` and data
  ## ``message``.
  ##
  ## Return ``true`` if message verification succeeded, ``false`` if
  ## verification failed.
  if len(sig.buffer) > 0:
    var hc: BrHashCompatContext
    var hash: array[32, byte]
    var check: array[32, byte]
    var impl = BrRsaPkcs1VrfyGetDefault()
    var kv = addr sha256Vtable
    kv.init(addr hc.vtable)
    if len(message) > 0:
      kv.update(addr hc.vtable, unsafeAddr message[0], len(message))
    else:
      kv.update(addr hc.vtable, nil, 0)
    kv.output(addr hc.vtable, addr hash[0])
    var oid = RsaOidSha256
    let res = impl(cast[ptr cuchar](addr sig.buffer[0]), len(sig.buffer),
                   cast[ptr cuchar](addr oid[0]),
                   len(check), addr pubkey.key, cast[ptr cuchar](addr check[0]))
    if res == 1:
      result = equalMem(addr check[0], addr hash[0], len(hash))
