# Copyright (c) 2023 zenywallet

import bearssl/bearssl_ssl
import bearssl/bearssl_rsa
import bearssl/bearssl_ec
import bearssl/bearssl_rand
import bearssl/bearssl_hash
import bearssl/bearssl_x509
import bearssl/bearssl_pem
import bytes

proc genKey*(keyFilePath: string = "privkey.pem") =
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
  doAssert prvLen == 32
  echo sk.x.toBytes(sk.xlen)

  var pubLen = br_ec_compute_pub(impl, addr pk, addr kbuf_pub, addr sk)
  doAssert pubLen == 65
  echo pk.q.toBytes(pk.qlen)

  var derLen = br_encode_ec_raw_der(nil, addr sk, addr pk)
  doAssert derLen > 0
  var buf = alloc0(derLen)
  derLen = br_encode_ec_raw_der(buf, addr sk, addr pk)
  doAssert derLen > 0

  var pemlen = br_pem_encode(nil, nil, derLen, "EC PRIVATE KEY", 0)
  var pemBuf = alloc0(pemlen + 1)
  var pemlen2 = br_pem_encode(pemBuf, buf, derLen, "EC PRIVATE KEY", 0)
  doAssert pemlen == pemlen2

  var f = open(keyFilePath, fmWrite)
  var wlen = f.writeBuffer(pemBuf, pemlen)
  doAssert wlen == pemlen.int
  f.close()

  dealloc(pemBuf)
  dealloc(buf)
