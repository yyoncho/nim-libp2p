import unittest
import ../libp2p/[cid, multihash, multicodec, errors]

suite "Content identifier CID test suite":

  test "CIDv0 test vector":
    var cid0Text = "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n"
    var cid0 = Cid.init(cid0Text)
    check:
      cid0.isOk == true
      $(cid0.value) == cid0Text
      cid0.value.version() == CIDv0
      cid0.value.contentType() == multiCodec("dag-pb")
      cid0.value.mhash().value.mcodec == multiCodec("sha2-256")

    var cidb0 = Cid.init("QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zIII")
    check:
      cidb0.isErr == true
      cidb0.error == errors.CidIncorrectError

  test "CIDv1 test vector":
    var cid1Text = "zb2rhhFAEMepUBbGyP1k8tGfz7BSciKXP6GHuUeUsJBaK6cqG"
    var chex = "015512209D8453505BDC6F269678E16B3E56" &
               "C2A2948A41F2C792617CC9611ED363C95B63"
    var cid1 = Cid.init(cid1Text)
    check:
      cid1.isOk == true
      $(cid1.value) == cid1Text
      cid1.value.version() == CIDv1
      cid1.value.contentType() == multiCodec("raw")
      cid1.value.mhash().value.mcodec == multiCodec("sha2-256")
      hex(cid1.value) == chex

  test "Comparison test":
    var msg = "Hello World!"
    var mmsg = "Hello World!Hello World!"
    var bmsg = cast[seq[byte]](msg)
    var bmmsg = cast[seq[byte]](mmsg)
    var cid0 = Cid.init(CIDv0, multiCodec("dag-pb"),
                        MultiHash.digest("sha2-256", bmsg).value)
    var cid1 = Cid.init(CIDv1, multiCodec("dag-pb"),
                        MultiHash.digest("sha2-256", bmsg).value)
    var cid2 = cid1
    var cid3 = cid0
    var cid4 = Cid.init(CIDv1, multiCodec("dag-cbor"),
                        MultiHash.digest("sha2-256", bmsg).value)
    var cid5 = Cid.init(CIDv1, multiCodec("dag-pb"),
                        MultiHash.digest("sha2-256", bmmsg).value)
    var cid6 = Cid.init(CIDv1, multiCodec("dag-pb"),
                        MultiHash.digest("keccak-256", bmsg).value)
    check:
      cid0.value == cid1.value
      cid1.value == cid2.value
      cid2.value == cid3.value
      cid3.value == cid0.value
      cid0.value != cid4.value
      cid1.value != cid5.value
      cid2.value != cid4.value
      cid3.value != cid6.value
