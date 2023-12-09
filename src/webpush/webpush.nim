# Copyright (c) 2023 zenywallet

import bearssl/bearssl_ssl
import bearssl/bearssl_rsa
import bearssl/bearssl_ec
import bearssl/bearssl_rand
import bearssl/bearssl_hash
import bearssl/bearssl_x509
import bearssl/bearssl_pem
import bytes
export bytes

const WebPushPrvKeyLen* = 32
const WebPushPubKeyLen* = 65

type
  WebPushKeyPair* = object
    prv: seq[byte]
    pub: seq[byte]
    sk: br_ec_private_key
    pk: br_ec_public_key

proc genKey*(): WebPushKeyPair =
  var seeder = br_prng_seeder_system(cast[cstringArray](nil))
  var rng: br_hmac_drbg_context
  br_hmac_drbg_init(addr rng, addr br_sha256_vtable, nil, 0)
  if seeder(addr rng.vtable) == 0: raise

  var impl: ptr br_ec_impl = br_ec_get_default()
  var sk: br_ec_private_key
  var kbuf_priv: array[BR_EC_KBUF_PRIV_MAX_SIZE, uint8]
  var pk: br_ec_public_key
  var kbuf_pub: array[BR_EC_KBUF_PUB_MAX_SIZE, uint8]
  var prvLen = br_ec_keygen(addr rng.vtable, impl, addr sk, addr kbuf_priv, BR_EC_secp256r1)
  doAssert prvLen == WebPushPrvKeyLen
  var pubLen = br_ec_compute_pub(impl, addr pk, addr kbuf_pub, addr sk)
  doAssert pubLen == WebPushPubKeyLen

  result.prv = sk.x.toBytes(sk.xlen)
  result.pub = pk.q.toBytes(pk.qlen)
  result.sk = br_ec_private_key(curve: sk.curve, x: addr result.prv[0], xlen: sk.xlen)
  result.pk = br_ec_public_key(curve: pk.curve, q: addr result.pub[0], qlen: pk.qlen)

proc clear*(pair: var WebPushKeyPair) =
  zeroMem(addr pair.sk, sizeof(pair.sk))
  zeroMem(addr pair.pk, sizeof(pair.pk))
  zeroMem(addr pair.prv[0], pair.prv.len)
  zeroMem(addr pair.pub[0], pair.pub.len)
  pair.prv = @[]
  pair.pub = @[]

proc save*(pair: WebPushKeyPair, keyFilePath: string = "privkey.pem") =
  var derLen = br_encode_ec_raw_der(nil, addr pair.sk, addr pair.pk)
  doAssert derLen > 0
  var buf = alloc0(derLen)
  derLen = br_encode_ec_raw_der(buf, addr pair.sk, addr pair.pk)
  doAssert derLen > 0

  var pemlen = br_pem_encode(nil, nil, derLen, "EC PRIVATE KEY", 0)
  var pemBuf = cast[ptr UncheckedArray[byte]](alloc0(pemlen + 1))
  var pemlen2 = br_pem_encode(pemBuf, buf, derLen, "EC PRIVATE KEY", 0)
  doAssert pemlen == pemlen2

  var f = open(keyFilePath, fmWrite)
  var pos = 0
  var left = pemlen
  while left > 0:
    var wlen = f.writeBuffer(addr pemBuf[pos], left)
    if wlen > 0:
      inc(pos, wlen)
      dec(left, wlen)
    else:
      raise
  f.close()

  dealloc(pemBuf)
  dealloc(buf)
