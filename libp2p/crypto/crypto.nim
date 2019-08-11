## Nim-Libp2p
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

## This module implements Public Key and Private Key interface for libp2p.
import rsa, ecnist, ed25519/ed25519
import ../protobuf/minprotobuf, ../vbuffer, ../errors
import nimcrypto/[rijndael, blowfish, sha, sha2, hash, hmac, utils]

# This is workaround for Nim's `import` bug
export rijndael, blowfish, sha, sha2, hash, hmac, utils, errors

type
  PKScheme* = enum
    RSA = 0,
    Ed25519,
    Secp256k1,
    ECDSA,
    NoSupport

  CipherScheme* = enum
    Aes128 = 0,
    Aes256,
    Blowfish

  DigestSheme* = enum
    Sha1,
    Sha256,
    Sha512

  ECDHEScheme* = EcCurveKind

  PublicKey* = object
    case scheme*: PKScheme
    of RSA:
      rsakey*: RsaPublicKey
    of Ed25519:
      edkey*: EdPublicKey
    of Secp256k1:
      discard
    of ECDSA:
      eckey*: EcPublicKey
    of NoSupport:
      discard

  PrivateKey* = object
    case scheme*: PKScheme
    of RSA:
      rsakey*: RsaPrivateKey
    of Ed25519:
      edkey*: EdPrivateKey
    of Secp256k1:
      discard
    of ECDSA:
      eckey*: EcPrivateKey
    of NoSupport:
      discard

  KeyPair* = object
    seckey*: PrivateKey
    pubkey*: PublicKey

  Secret* = object
    ivsize*: int
    keysize*: int
    macsize*: int
    data*: seq[byte]

  Signature* = object
    data*: seq[byte]

const
  SupportedSchemes* = {RSA, Ed25519, ECDSA}
  SupportedSchemesInt* = {int8(RSA), int8(Ed25519), int8(ECDSA)}

proc random*(t: typedesc[PrivateKey], scheme: PKScheme,
             bits = DefaultKeySize): Result[PrivateKey, errors.Error] =
  ## Generate random private key for scheme ``scheme``.
  ##
  ## ``bits`` is number of bits for RSA key, ``bits`` value must be in
  ## [512, 4096], default value is 2048 bits.
  if scheme notin SupportedSchemes:
    result.err(errors.NoSupportError)
    return
  var key = PrivateKey(scheme: scheme)
  if scheme == RSA:
    let res = RsaPrivateKey.random(bits)
    if res.isErr:
      result.err(res.error)
      return
    key.rsakey = res.value
  elif scheme == Ed25519:
    let res = EdPrivateKey.random()
    if res.isErr:
      result.err(res.error)
      return
    key.edkey = res
  elif scheme == ECDSA:
    let res = EcPrivateKey.random(Secp256r1)
    if res.isErr:
      result.err(res.error)
      return
    key.eckey = res
  result.ok(key)

proc random*(t: typedesc[KeyPair], scheme: PKScheme,
             bits = DefaultKeySize): Result[KeyPair, errors.Error] =
  ## Generate random key pair for scheme ``scheme``.
  ##
  ## ``bits`` is number of bits for RSA key, ``bits`` value must be in
  ## [512, 4096], default value is 2048 bits.
  if scheme notin SupportedSchemes:
    result.err(errors.NoSupportError)
    return
  var pair = KeyPair(seckey: PrivateKey(scheme: scheme),
                     pubkey: PublicKey(scheme: scheme))
  if scheme == RSA:
    let res = RsaKeyPair.random(bits)
    if res.isErr:
      result.err(res.error)
      return
    pair.seckey.rsakey = res.value.seckey
    pair.pubkey.rsakey = res.value.pubkey
  elif scheme == Ed25519:
    let res = EdKeyPair.random()
    if res.isErr:
      result.err(res.error)
      return
    pair.seckey.edkey = res.value.seckey
    pair.pubkey.edkey = res.value.pubkey
  elif scheme == ECDSA:
    let res = EcKeyPair.random(Secp256r1)
    if res.isErr:
      result.err(res.error)
      return
    pair.seckey.eckey = res.value.seckey
    pair.pubkey.eckey = res.value.pubkey
  result.ok(pair)

proc getKey*(key: PrivateKey): PublicKey =
  ## Get public key from corresponding private key ``key``.
  result = PublicKey(scheme: key.scheme)
  if key.scheme == RSA:
    result.rsakey = key.rsakey.getKey()
  elif key.scheme == Ed25519:
    result.edkey = key.edkey.getKey()
  elif key.scheme == ECDSA:
    result.eckey = key.eckey.getKey()

proc toRawBytes*(key: PrivateKey, data: var openarray[byte]): int =
  ## Serialize private key ``key`` (using scheme's own serialization) and store
  ## it to ``data``.
  ##
  ## Returns number of bytes (octets) needed to store private key ``key``.
  if key.scheme == RSA:
    result = key.rsakey.toBytes(data)
  elif key.scheme == Ed25519:
    result = key.edkey.toBytes(data)
  elif key.scheme == ECDSA:
    result = key.eckey.toBytes(data)

proc toRawBytes*(key: PublicKey, data: var openarray[byte]): int =
  ## Serialize public key ``key`` (using scheme's own serialization) and store
  ## it to ``data``.
  ##
  ## Returns number of bytes (octets) needed to store public key ``key``.
  if key.scheme == RSA:
    result = key.rsakey.toBytes(data)
  elif key.scheme == Ed25519:
    result = key.edkey.toBytes(data)
  elif key.scheme == ECDSA:
    result = key.eckey.toBytes(data)

proc getRawBytes*(key: PrivateKey): seq[byte] =
  ## Return private key ``key`` in binary form (using scheme's own
  ## serialization).
  if key.scheme == RSA:
    result = key.rsakey.getBytes()
  elif key.scheme == Ed25519:
    result = key.edkey.getBytes()
  elif key.scheme == ECDSA:
    result = key.eckey.getBytes()

proc getRawBytes*(key: PublicKey): seq[byte] =
  ## Return public key ``key`` in binary form (using scheme's own
  ## serialization).
  if key.scheme == RSA:
    result = key.rsakey.getBytes()
  elif key.scheme == Ed25519:
    result = key.edkey.getBytes()
  elif key.scheme == ECDSA:
    result = key.eckey.getBytes()

proc toBytes*(key: PrivateKey, data: var openarray[byte]): int =
  ## Serialize private key ``key`` (using libp2p protobuf scheme) and store
  ## it to ``data``.
  ##
  ## Returns number of bytes (octets) needed to store private key ``key``.
  var msg = ProtoBuffer.init()
  msg.write(ProtoField.init(1, cast[uint64](key.scheme)))
  msg.write(ProtoField.init(2, key.getRawBytes()))
  msg.finish()
  result = len(msg.buffer)
  if len(data) >= result:
    copyMem(addr data[0], addr msg.buffer[0], len(msg.buffer))

proc toBytes*(key: PublicKey, data: var openarray[byte]): int =
  ## Serialize public key ``key`` (using libp2p protobuf scheme) and store
  ## it to ``data``.
  ##
  ## Returns number of bytes (octets) needed to store public key ``key``.
  var msg = ProtoBuffer.init()
  msg.write(ProtoField.init(1, cast[uint64](key.scheme)))
  msg.write(ProtoField.init(2, key.getRawBytes()))
  msg.finish()
  result = len(msg.buffer)
  if len(data) >= result:
    copyMem(addr data[0], addr msg.buffer[0], len(msg.buffer))

proc toBytes*(sig: Signature, data: var openarray[byte]): int =
  ## Serialize signature ``sig`` and store it to ``data``.
  ##
  ## Returns number of bytes (octets) needed to store signature ``sig``.
  result = len(sig.data)
  if len(data) >= result:
    copyMem(addr data[0], unsafeAddr sig.data[0], len(sig.data))

proc getBytes*(key: PrivateKey): seq[byte] =
  ## Return private key ``key`` in binary form (using libp2p's protobuf
  ## serialization).
  var msg = ProtoBuffer.init()
  msg.write(ProtoField.init(1, cast[uint64](key.scheme)))
  msg.write(ProtoField.init(2, key.getRawBytes()))
  msg.finish()
  result = msg.buffer

proc getBytes*(key: PublicKey): seq[byte] =
  ## Return public key ``key`` in binary form (using libp2p's protobuf
  ## serialization).
  var msg = ProtoBuffer.init()
  msg.write(ProtoField.init(1, cast[uint64](key.scheme)))
  msg.write(ProtoField.init(2, key.getRawBytes()))
  msg.finish()
  result = msg.buffer

proc getBytes*(sig: Signature): seq[byte] =
  ## Return signature ``sig`` in binary form.
  result = sig.data

proc init*(tkey: typedesc[PrivateKey],
           data: openarray[byte]): Result[PrivateKey, errors.Error] =
  ## Initialize private key from libp2p's protobuf serialized raw binary form
  ## ``data``.
  if len(data) == 0:
    result.err(errors.IncompleteError)
    return

  var pb = ProtoBuffer.init(data)

  var id = pb.getVarintValue(1)
  if id.isErr:
    result.err(errors.CryptoIncorrectBinaryFormError)
    return

  var buffer = pb.getBytes(2)
  if buffer.isErr:
    result.err(errors.CryptoIncorrectBinaryFormError)
    return

  if cast[int8](id) notin SupportedSchemesInt:
    result.err(errors.CryptoSchemeNoSupportError)
    return

  let scheme = cast[PKScheme](cast[int8](id))
  var key = PrivateKey(scheme: scheme)
  if scheme == RSA:
    let res = RsaPrivateKey.init(buffer.value)
    if res.isErr:
      result.err(errors.CryptoIncorrectBinaryFormError)
      return
    key.rsakey = res.value
  elif scheme == Ed25519:
    let res = EdPrivateKey.init(buffer.value)
    if res.isErr:
      result.err(errors.CryptoIncorrectBinaryFormError)
      return
    key.edkey = res.value
  elif scheme == ECDSA:
    let res = EcPrivateKey.init(buffer.value)
    if res.isErr:
      result.err(errors.CryptoIncorrectBinaryFormError)
      return
    key.eckey = res.value

  result.ok(key)

proc init*(tkey: typedesc[PublicKey],
           data: openarray[byte]): Result[PublicKey, errors.Error] =
  ## Initialize public key from libp2p's protobuf serialized raw binary form
  ## ``data``.
  if len(data) == 0:
    result.err(errors.IncompleteError)
    return

  var pb = ProtoBuffer.init(data)

  var id = pb.getVarintValue(1)
  if id.isErr:
    result.err(errors.CryptoIncorrectBinaryFormError)
    return

  var buffer = pb.getBytes(2)
  if buffer.isErr:
    result.err(errors.CryptoIncorrectBinaryFormError)
    return

  if cast[int8](id) notin SupportedSchemesInt:
    result.err(errors.CryptoSchemeNoSupportError)
    return

  let scheme = cast[PKScheme](cast[int8](id))
  var key = PublicKey(scheme: scheme)
  if scheme == RSA:
    let res = RsaPublicKey.init(buffer.value)
    if res.isErr:
      result.err(errors.CryptoIncorrectBinaryFormError)
      return
    key.rsakey = res.value
  elif scheme == Ed25519:
    let res = EdPublicKey.init(buffer.value)
    if res.isErr:
      result.err(errors.CryptoIncorrectBinaryFormError)
      return
    key.edkey = res.value
  elif scheme == ECDSA:
    let res = EcPublicKey.init(buffer.value)
    if res.isErr:
      result.err(errors.CryptoIncorrectBinaryFormError)
      return
    key.eckey = res.value

  result.ok(key)

proc init*(tsig: typedesc[Signature],
           data: openarray[byte]): Result[PublicKey, errors.Error] =
  ## Initialize signature from raw binary form ``data``.
  if len(data) == 0:
    result.err(errors.IncompleteError)
    return
  result.ok(Signature(data: @data))

proc init*(tkey: typedesc[PrivateKey],
           data: string): Result[PrivateKey, errors.Error] =
  ## Initialize private key from libp2p's protobuf serialized
  ## hexadecimal string representation ``data``.
  var buffer: seq[byte]
  try:
    var buffer = fromHex(data)
  except:
    result.err(IncorrectHexadecimalError)
    return
  result = tkey.init(buffer)

proc init*(tkey: typedesc[PublicKey],
           data: string): Result[PrivateKey, errors.Error] =
  ## Initialize public key from libp2p's protobuf serialized
  ## hexadecimal string representation ``data``.
  var buffer: seq[byte]
  try:
    var buffer = fromHex(data)
  except:
    result.err(IncorrectHexadecimalError)
    return
  result = tkey.init(buffer)

proc init*(tsig: typedesc[Signature],
           data: string): Result[PrivateKey, errors.Error] =
  ## Initialize signature ``sig`` from serialized hexadecimal string
  ## representation.
  var buffer: seq[byte]
  try:
    var buffer = fromHex(data)
  except:
    result.err(IncorrectHexadecimalError)
    return
  result = tsig.init(buffer)

proc `==`*(key1, key2: PublicKey): bool =
  ## Return ``true`` if two public keys ``key1`` and ``key2`` of the same
  ## scheme and equal.
  if key1.scheme == key2.scheme:
    if key1.scheme == RSA:
      result = (key1.rsakey == key2.rsakey)
    elif key1.scheme == Ed25519:
      result = (key1.edkey == key2.edkey)
    elif key1.scheme == ECDSA:
      result = (key1.eckey == key2.eckey)

proc `==`*(key1, key2: PrivateKey): bool =
  ## Return ``true`` if two private keys ``key1`` and ``key2`` of the same
  ## scheme and equal.
  if key1.scheme == key2.scheme:
    if key1.scheme == RSA:
      result = (key1.rsakey == key2.rsakey)
    elif key1.scheme == Ed25519:
      result = (key1.edkey == key2.edkey)
    elif key1.scheme == ECDSA:
      result = (key1.eckey == key2.eckey)

proc `$`*(key: PrivateKey): string =
  ## Get string representation of private key ``key``.
  if key.scheme == RSA:
    result = $(key.rsakey)
  elif key.scheme == Ed25519:
    result = "Ed25519 key ("
    result.add($(key.edkey))
    result.add(")")
  elif key.scheme == ECDSA:
    result = "Secp256r1 key ("
    result.add($(key.eckey))
    result.add(")")

proc `$`*(key: PublicKey): string =
  ## Get string representation of public key ``key``.
  if key.scheme == RSA:
    result = $(key.rsakey)
  elif key.scheme == Ed25519:
    result = "Ed25519 key ("
    result.add($(key.edkey))
    result.add(")")
  elif key.scheme == ECDSA:
    result = "Secp256r1 key ("
    result.add($(key.eckey))
    result.add(")")

proc `$`*(sig: Signature): string =
  ## Get string representation of signature ``sig``.
  result = toHex(sig.data)

proc sign*(key: PrivateKey, data: openarray[byte]): Signature =
  ## Sign message ``data`` using private key ``key`` and return generated
  ## signature in raw binary form.
  if key.scheme == RSA:
    var sig = key.rsakey.sign(data)
    result.data = sig.getBytes()
  elif key.scheme == Ed25519:
    var sig = key.edkey.sign(data)
    result.data = sig.getBytes()
  elif key.scheme == ECDSA:
    var sig = key.eckey.sign(data)
    result.data = sig.getBytes()

proc verify*(sig: Signature, message: openarray[byte], key: PublicKey): bool =
  ## Verify signature ``sig`` using message ``message`` and public key ``key``.
  ## Return ``true`` if message signature is valid.
  if key.scheme == RSA:
    let res = RsaSignature.init(sig.data)
    if res.isOk:
      result = res.value.verify(message, key.rsakey)
    else:
      result = false
  elif key.scheme == Ed25519:
    let res = EdSignature.init(sig.data)
    if res.isOk:
      result = res.value.verify(message, key.edkey)
    else:
      result = false
  elif key.scheme == ECDSA:
    let res = EcSignature.init(sig.data)
    if res.isOk:
      result = res.value.verify(message, key.eckey)
    else:
      result = false
  else:
    result = false

template makeSecret(buffer, hmactype, secret, seed) =
  var ctx: hmactype
  var j = 0
  # We need to strip leading zeros, because Go bigint serialization do it.
  var offset = 0
  for i in 0..<len(secret):
    if secret[i] != 0x00'u8:
      break
    inc(offset)
  ctx.init(secret.toOpenArray(offset, len(secret) - 1))
  ctx.update(seed)
  var a = ctx.finish()
  while j < len(buffer):
    ctx.init(secret.toOpenArray(offset, len(secret) - 1))
    ctx.update(a.data)
    ctx.update(seed)
    var b = ctx.finish()
    var todo = len(b.data)
    if j + todo > len(buffer):
      todo = len(buffer) - j
    copyMem(addr buffer[j], addr b.data[0], todo)
    j += todo
    ctx.init(secret.toOpenArray(offset, len(secret) - 1))
    ctx.update(a.data)
    a = ctx.finish()

proc stretchKeys*(cipherScheme: CipherScheme, hashScheme: DigestSheme,
                  secret: openarray[byte]): Secret =
  ## Expand shared secret to cryptographic keys.
  if cipherScheme == Aes128:
    result.ivsize = aes128.sizeBlock
    result.keysize = aes128.sizeKey
  elif cipherScheme == Aes256:
    result.ivsize = aes256.sizeBlock
    result.keysize = aes256.sizeKey
  elif cipherScheme == Blowfish:
    result.ivsize = 8
    result.keysize = 32

  var seed = "key expansion"
  result.macsize = 20
  let length = result.ivsize + result.keysize + result.macsize
  result.data = newSeq[byte](2 * length)

  if hashScheme == Sha256:
    makeSecret(result.data, HMAC[sha256], secret, seed)
  elif hashScheme == Sha512:
    makeSecret(result.data, HMAC[sha512], secret, seed)
  elif hashScheme == Sha1:
    makeSecret(result.data, HMAC[sha1], secret, seed)

template goffset*(secret, id, o: untyped): untyped =
  id * (len(secret.data) shr 1) + o

template ivOpenArray*(secret: Secret, id: int): untyped =
  toOpenArray(secret.data, goffset(secret, id, 0),
              goffset(secret, id, secret.ivsize - 1))

template keyOpenArray*(secret: Secret, id: int): untyped =
  toOpenArray(secret.data, goffset(secret, id, secret.ivsize),
              goffset(secret, id, secret.ivsize + secret.keysize - 1))

template macOpenArray*(secret: Secret, id: int): untyped =
  toOpenArray(secret.data, goffset(secret, id, secret.ivsize + secret.keysize),
       goffset(secret, id, secret.ivsize + secret.keysize + secret.macsize - 1))

proc iv*(secret: Secret, id: int): seq[byte] {.inline.} =
  ## Get array of bytes with with initial vector.
  result = newSeq[byte](secret.ivsize)
  var offset = if id == 0: 0 else: (len(secret.data) div 2)
  copyMem(addr result[0], unsafeAddr secret.data[offset], secret.ivsize)

proc key*(secret: Secret, id: int): seq[byte] {.inline.} =
  result = newSeq[byte](secret.keysize)
  var offset = if id == 0: 0 else: (len(secret.data) div 2)
  offset += secret.ivsize
  copyMem(addr result[0], unsafeAddr secret.data[offset], secret.keysize)

proc mac*(secret: Secret, id: int): seq[byte] {.inline.} =
  result = newSeq[byte](secret.macsize)
  var offset = if id == 0: 0 else: (len(secret.data) div 2)
  offset += secret.ivsize + secret.keysize
  copyMem(addr result[0], unsafeAddr secret.data[offset], secret.macsize)

proc ephemeral*(scheme: ECDHEScheme): Result[KeyPair, errors.Error] =
  ## Generate ephemeral keys used to perform ECDHE.
  var keypair: EcKeyPair
  if scheme == Secp256r1:
    let res = EcKeyPair.random(Secp256r1)
    if res.isErr:
      result.err(res.error)
      return
    keypair = res.value
  elif scheme == Secp384r1:
    let res = EcKeyPair.random(Secp384r1)
    if res.isErr:
      result.err(res.error)
      return
    keypair = res.value
  elif scheme == Secp521r1:
    let res = EcKeyPair.random(Secp521r1)
    if res.isErr:
      result.err(res.error)
      return
    keypair = res.value
  var pair = KeyPair()
  pair.seckey = PrivateKey(scheme: ECDSA)
  pair.pubkey = PublicKey(scheme: ECDSA)
  pair.seckey.eckey = keypair.seckey
  pair.pubkey.eckey = keypair.pubkey
  result.ok(pair)

proc makeSecret*(remoteEPublic: PublicKey,
                 localEPrivate: PrivateKey): Result[seq[byte], errors.Error] =
  ## Calculate shared secret using remote ephemeral public key
  ## ``remoteEPublic`` and local ephemeral private key ``localEPrivate``.
  if remoteEPublic.scheme != ECDSA:
    result.err(errors.CryptoEcdheIncorrectSchemeError)
    return

  if localEPrivate.scheme != remoteEPublic.scheme:
    result.err(errors.CryptoEcdheUnequalSchemesError)
    return

  result = getSecret(remoteEPublic.eckey, localEPrivate.eckey)


## Serialization/Deserialization helpers

proc write*(vb: var VBuffer,
            pubkey: PublicKey): Result[int, errors.Error] {.inline.} =
  ## Write PublicKey value ``pubkey`` to buffer ``vb``.
  result = vb.writeSeq(pubkey.getBytes())

proc write*(vb: var VBuffer,
            seckey: PrivateKey): Result[int, errors.Error] {.inline.} =
  ## Write PrivateKey value ``seckey`` to buffer ``vb``.
  result = vb.writeSeq(seckey.getBytes())

proc write*(vb: var VBuffer,
            sig: Signature): Result[int, errors.Error] {.inline.} =
  ## Write Signature value ``sig`` to buffer ``vb``.
  result = vb.writeSeq(sig.getBytes())

proc init*(t: typedesc[ProtoField],
           index: int, pubkey: PublicKey): ProtoField =
  ## Initialize ProtoField with PublicKey ``pubkey``.
  result = ProtoField.init(index, pubkey.getBytes())

proc init*(t: typedesc[ProtoField],
           index: int, seckey: PrivateKey): ProtoField =
  ## Initialize ProtoField with PrivateKey ``seckey``.
  result = ProtoField.init(index, seckey.getBytes())

proc init*(t: typedesc[ProtoField], index: int, sig: Signature): ProtoField =
  ## Initialize ProtoField with Signature ``sig``.
  result = ProtoField.init(index, sig.getBytes())

proc getValue*(tkey: typedesc[PublicKey], data: var ProtoBuffer,
               field: int): Result[PublicKey, errors.Error] =
  ## Read ``PublicKey`` from ProtoBuf's message and validate it.
  let r0 = getLengthValue(data, field)
  if r0.isErr:
    result.err(r0.error)
    return
  let r1 = PublicKey.init(r0.value)
  if r1.isErr:
    result.err(r1.error)
    return
  result.ok(r1.value)

proc getValue*(tkey: typedesc[PrivateKey], data: var ProtoBuffer,
               field: int): Result[PrivateKey, errors.Error] =
  ## Read ``PrivateKey`` from ProtoBuf's message and validate it.
  let r0 = getLengthValue(data, field)
  if r0.isErr:
    result.err(r0.error)
    return
  let r1 = PrivateKey.init(r0.value)
  if r1.isErr:
    result.err(r1.error)
    return
  result.ok(r1.value)

proc getValue*(tsig: typedesc[Signature], data: var ProtoBuffer,
               field: int): Result[Signature, errors.Error] =
  ## Read ``Signature`` from ProtoBuf's message and validate it.
  let r0 = getLengthValue(data, field)
  if r0.isErr:
    result.err(r0.error)
    return
  let r1 = Signature.init(r0.value)
  if r1.isErr:
    result.err(r1.error)
    return
  result.ok(r1.value)
