## Nim-LibP2P
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

## This module implementes CID (Content IDentifier).
import tables
import multibase, multicodec, multihash, vbuffer, varint, base58, errors
export errors

type
  CidVersion* = enum
    CIDvIncorrect, CIDv0, CIDv1, CIDvReserved

  Cid* = object
    cidver*: CidVersion
    mcodec*: MultiCodec
    hpos*: int
    data*: VBuffer

const
  ContentIdsList = [
    multiCodec("raw"),
    multiCodec("dag-pb"),
    multiCodec("dag-cbor"),
    multiCodec("dag-json"),
    multiCodec("git-raw"),
    multiCodec("eth-block"),
    multiCodec("eth-block-list"),
    multiCodec("eth-tx-trie"),
    multiCodec("eth-tx"),
    multiCodec("eth-tx-receipt-trie"),
    multiCodec("eth-tx-receipt"),
    multiCodec("eth-state-trie"),
    multiCodec("eth-account-snapshot"),
    multiCodec("eth-storage-trie"),
    multiCodec("bitcoin-block"),
    multiCodec("bitcoin-tx"),
    multiCodec("zcash-block"),
    multiCodec("zcash-tx"),
    multiCodec("stellar-block"),
    multiCodec("stellar-tx"),
    multiCodec("decred-block"),
    multiCodec("decred-tx"),
    multiCodec("dash-block"),
    multiCodec("dash-tx"),
    multiCodec("torrent-info"),
    multiCodec("torrent-file"),
    multiCodec("ed25519-pub")
  ]

proc initCidCodeTable(): Table[int, MultiCodec] {.compileTime.} =
  result = initTable[int, MultiCodec]()
  for item in ContentIdsList:
    result[int(item)] = item

const
  CodeContentIds = initCidCodeTable()

proc decode(data: openarray[byte]): Result[Cid, errors.Error] {.inline.} =
  if len(data) == 34:
    if data[0] == 0x12'u8 and data[1] == 0x20'u8:
      result.ok(Cid(cidver: CIDv0, mcodec: multiCodec("dag-pb"), hpos: 0,
                    data: VBuffer.init(data)))
      return

  var version, codec: uint64
  var offset: int
  var vb = VBuffer.init(data)
  if vb.isEmpty():
    result.err(errors.CidIncorrectError)
    return

  let r0 = vb.readVarint(version)
  if r0.isErr:
    result.err(errors.CidIncorrectError)
    return
  offset += r0.value
  if version != 1'u64:
    result.err(errors.CidIncorrectError)
    return

  let r1 = vb.readVarint(codec)
  if r1.isErr:
    result.err(errors.CidIncorrectError)
    return
  offset += r1.value
  var mcodec = CodeContentIds.getOrDefault(cast[int](codec),
                                           InvalidMultiCodec)
  if mcodec == InvalidMultiCodec:
    result.err(errors.CidIncorrectError)
    return

  if not MultiHash.validate(vb.buffer.toOpenArray(vb.offset,
                                                  len(vb.buffer) - 1)):
    result.err(errors.CidIncorrectError)
    return

  vb.finish()
  result.ok(Cid(cidver: CIDv1, mcodec: mcodec, hpos: offset, data: vb))

proc decode(data: openarray[char]): Result[Cid, errors.Error] {.inline.} =
  var buffer: seq[byte]
  var plen = 0
  if len(data) < 2:
    result.err(errors.CidIncorrectError)
    return

  if len(data) == 46:
    if data[0] == 'Q' and data[1] == 'm':
      buffer = newSeq[byte](BTCBase58.decodedLength(len(data)))
      let res = BTCBase58.decode(data, buffer)
      if res.isErr:
        result.err(errors.CidIncorrectError)
        return
      buffer.setLen(res.value)
      result = decode(buffer)
      return

  let r0 = MultiBase.decodedLength(data[0], len(data))
  if r0.isErr:
    result.err(errors.CidIncorrectError)
    return

  buffer = newSeq[byte](r0.value)
  let r1 = MultiBase.decode(data, buffer)
  if r1.isErr:
    result.err(errors.CidIncorrectError)
    return

  buffer.setLen(r1.value)
  if buffer[0] == 0x12'u8:
    result.err(errors.CidIncorrectError)
    return

  result = decode(buffer)

proc validate*(ctype: typedesc[Cid], data: openarray[byte]): bool =
  ## Returns ``true`` is data has valid binary CID representation.
  var version, codec: uint64
  if len(data) < 2:
    return false
  let last = len(data) - 1
  if len(data) == 34:
    if data[0] == 0x12'u8 and data[1] == 0x20'u8:
      return true
  var offset = 0

  let r0 = LP.getUVarint(data.toOpenArray(offset, last))
  if r0.isErr:
    return false
  version = r0.value.value
  offset += r0.value.length
  if version != 1'u64:
    return false
  if offset >= len(data):
    return false

  let r1 = LP.getUVarint(data.toOpenArray(offset, last))
  if r1.isErr:
    return false
  codec = r1.value.value
  offset += r1.value.length
  if offset >= len(data):
    return false

  var mcodec = CodeContentIds.getOrDefault(cast[int](codec), InvalidMultiCodec)
  if mcodec == InvalidMultiCodec:
    return false
  if not MultiHash.validate(data.toOpenArray(offset, last)):
    return false
  result = true

proc mhash*(cid: Cid): Result[MultiHash, errors.Error] =
  ## Returns MultiHash part of CID.
  if cid.cidver notin {CIDv0, CIDv1}:
    result.err(CidIncorrectError)
    return
  result = MultiHash.init(cid.data.buffer.toOpenArray(cid.hpos,
                                                      len(cid.data) - 1))

proc contentType*(cid: Cid): MultiCodec =
  ## Returns content type part of CID
  result = cid.mcodec

proc version*(cid: Cid): CidVersion =
  ## Returns CID version
  result = cid.cidver

proc init*[T: char|byte](ctype: typedesc[Cid],
                         data: openarray[T]): Result[Cid, errors.Error] =
  ## Create new content identifier using array of bytes or string ``data``.
  result = decode(data)

proc init*(ctype: typedesc[Cid], version: CidVersion, content: MultiCodec,
           hash: MultiHash): Result[Cid, errors.Error] =
  ## Create new content identifier using content type ``content`` and
  ## MultiHash ``hash`` using version ``version``.
  ##
  ## To create ``CIDv0`` you need to use:
  ## Cid.init(CIDv0, multiCodec("dag-pb"), MultiHash.digest("sha2-256", data))
  ##
  ## All other encodings and hashes are not supported by CIDv0.
  var cid: Cid

  if version == CIDv0:
    if content != multiCodec("dag-pb"):
      result.err(CidIncorrectContentType)
      return
    if hash.mcodec != multiCodec("sha2-256"):
      result.err(CidIncorrectHashType)
      return
    var vb = VBuffer.init()
    discard vb.write(hash)
    vb.finish()
    result.ok(Cid(cidver: CIDv0, mcodec: content, hpos: 0, data: vb))
  elif version == CIDv1:
    let mcodec = CodeContentIds.getOrDefault(cast[int](content),
                                             InvalidMultiCodec)
    if mcodec == InvalidMultiCodec:
      result.err(CidIncorrectContentType)
      return
    var vb = VBuffer.init()
    discard vb.writeVarint(1'u64)
    discard vb.write(mcodec)
    let hpos = len(vb.buffer)
    discard vb.write(hash)
    vb.finish()
    result.ok(Cid(cidver: CIDv1, mcodec: mcodec, hpos: hpos, data: vb))
  else:
    result.err(errors.CidIncorrectVersion)
    return

proc `==`*(a: Cid, b: Cid): bool =
  ## Compares content identifiers ``a`` and ``b``, returns ``true`` if hashes
  ## are equal, ``false`` otherwise.
  if a.mcodec == b.mcodec:
    var ah, bh: MultiHash
    let r0 = MultiHash.decode(a.data.buffer.toOpenArray(a.hpos,
                                                        len(a.data) - 1))
    let r1 = MultiHash.decode(b.data.buffer.toOpenArray(b.hpos,
                                                        len(b.data) - 1))
    if r0.isErr or r1.isErr:
      return false
    result = (r0.value == r1.value)

proc base58*(cid: Cid): string =
  ## Get BASE58 encoded string representation of content identifier ``cid``.
  result = BTCBase58.encode(cid.data.buffer)

proc hex*(cid: Cid): string =
  ## Get hexadecimal string representation of content identifier ``cid``.
  result = $(cid.data)

proc repr*(cid: Cid): string =
  ## Get string representation of content identifier ``cid``.
  result = $(cid.cidver)
  result.add("/")
  result.add($(cid.mcodec))
  result.add("/")
  result.add($(cid.mhash()))

proc write*(vb: var VBuffer, cid: Cid): Result[int, errors.Error] {.inline.} =
  ## Write CID value ``cid`` to buffer ``vb``.
  result = vb.writeArray(cid.data.buffer)

proc encode*(mbtype: typedesc[MultiBase], encoding: string,
             cid: Cid): Result[string, errors.Error] {.inline.} =
  ## Get MultiBase encoded representation of ``cid`` using encoding
  ## ``encoding``.
  result = MultiBase.encode(encoding, cid.data.buffer)

proc `$`*(cid: Cid): string =
  ## Return official string representation of content identifier ``cid``.
  if cid.cidver == CIDv0:
    result = BTCBase58.encode(cid.data.buffer)
  elif cid.cidver == CIDv1:
    result = MultiBase.Base58Btc.encode(cid.data.buffer)
