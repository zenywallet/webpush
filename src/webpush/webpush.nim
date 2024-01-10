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
    prv*: seq[byte]
    pub*: seq[byte]
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

type
  PemObj = object
    name: string
    data: seq[byte]

  PemObjs = seq[PemObj]

proc decodePem(pemData: string): PemObjs =
  var pemData = pemData
  if pemData[pemData.len - 1] != '\n':
    pemData.add("\n")

  var pc: br_pem_decoder_context
  br_pem_decoder_init(addr pc)

  proc dest(dest_ctx: pointer; src: pointer; len: csize_t) {.cdecl.} =
    let pBuf = cast[ptr seq[byte]](dest_ctx)
    let srcBytes = cast[ptr UncheckedArray[byte]](src).toBytes(len)
    pBuf[].add(srcBytes)

  var buf: seq[byte] = @[]
  br_pem_decoder_setdest(addr pc, dest, cast[pointer](addr buf))

  var len = pemData.len
  var pos = 0
  var pemObj: PemObj

  while len > 0:
    var tlen = br_pem_decoder_push(addr pc, addr pemData[pos], len.csize_t).int
    dec(len, tlen)
    inc(pos, tlen)
    case br_pem_decoder_event(addr pc)
    of BR_PEM_BEGIN_OBJ:
      pemObj.name = $br_pem_decoder_name(addr pc)
    of BR_PEM_END_OBJ:
      if buf.len > 0:
        pemObj.data = buf
        zeroMem(addr buf[0], buf.len)
        buf = @[]
        result.add(pemObj)
        zeroMem(addr pemObj.name[0], pemObj.name.len)
        pemObj.name = ""
        zeroMem(addr pemObj.data[0], pemObj.data.len)
        pemObj.data = @[]
    of BR_PEM_ERROR:
      raise
    else:
      raise

proc clearPemObjs(pemObjs: var PemObjs) =
  for i in 0..<pemObjs.len:
    zeroMem(addr pemObjs[i].name[0], pemObjs[i].name.len)
    pemObjs[i].name = ""
    zeroMem(addr pemObjs[i].data[0], pemObjs[i].data.len)
    pemObjs[i].data = @[]
  pemObjs = @[]

type
  CertPrivateKeyType* {.pure.} = enum
    None
    RSA
    EC

  CertPrivateKey* = object
    case keyType*: CertPrivateKeyType
    of CertPrivateKeyType.None:
      discard
    of CertPrivateKeyType.RSA:
      rsa*: ptr br_rsa_private_key
    of CertPrivateKeyType.EC:
      ec*: ptr br_ec_private_key

proc decodeCertPrivateKey(data: seq[byte]): CertPrivateKey =
  var dc: br_skey_decoder_context
  br_skey_decoder_init(addr dc)
  br_skey_decoder_push(addr dc, unsafeAddr data[0], data.len.csize_t)
  let err = br_skey_decoder_last_error(addr dc)
  if err != 0:
    return CertPrivateKey(keyType: CertPrivateKeyType.None)

  let keyType = br_skey_decoder_key_type(addr dc)
  case keyType
  of BR_KEYTYPE_RSA:
    var rk = br_skey_decoder_get_rsa(addr dc)
    var sk = cast[ptr br_rsa_private_key](allocShared0(sizeof(br_rsa_private_key)))
    sk.n_bitlen = rk.n_bitlen
    sk.p = cast[ptr uint8](allocShared0(rk.plen))
    copyMem(sk.p, rk.p, rk.plen)
    sk.plen = rk.plen
    sk.q = cast[ptr uint8](allocShared0(rk.qlen))
    copyMem(sk.q, rk.q, rk.qlen)
    sk.qlen = rk.qlen
    sk.dp = cast[ptr uint8](allocShared0(rk.dplen))
    copyMem(sk.dp, rk.dp, rk.dplen)
    sk.dplen = rk.dplen
    sk.dq = cast[ptr uint8](allocShared0(rk.dqlen))
    copyMem(sk.dq, rk.dq, rk.dqlen)
    sk.dqlen = rk.dqlen
    sk.iq = cast[ptr uint8](allocShared0(rk.iqlen))
    copyMem(sk.iq, rk.iq, rk.iqlen)
    sk.iqlen = rk.iqlen
    zeroMem(addr dc, sizeof(br_skey_decoder_context))
    return CertPrivateKey(keyType: CertPrivateKeyType.RSA, rsa: sk)

  of BR_KEYTYPE_EC:
    var ek = br_skey_decoder_get_ec(addr dc)
    var sk = cast[ptr br_ec_private_key](allocShared0(sizeof(br_ec_private_key)))
    sk.curve = ek.curve
    sk.x = cast[ptr uint8](allocShared0(ek.xlen))
    copyMem(sk.x, ek.x, ek.xlen)
    sk.xlen = ek.xlen
    zeroMem(addr dc, sizeof(br_skey_decoder_context))
    return CertPrivateKey(keyType: CertPrivateKeyType.EC, ec: sk)

  else:
    return CertPrivateKey(keyType: CertPrivateKeyType.None)

proc freeCertPrivateKey(certPrivKey: var CertPrivateKey) =
  case certPrivKey.keyType
  of CertPrivateKeyType.RSA:
    if not certPrivKey.rsa.isNil:
      zeroMem(certPrivKey.rsa.iq, certPrivKey.rsa.iqlen)
      zeroMem(certPrivKey.rsa.dq, certPrivKey.rsa.dqlen)
      zeroMem(certPrivKey.rsa.dp, certPrivKey.rsa.dplen)
      zeroMem(certPrivKey.rsa.q, certPrivKey.rsa.qlen)
      zeroMem(certPrivKey.rsa.p, certPrivKey.rsa.plen)
      deallocShared(certPrivKey.rsa.iq)
      deallocShared(certPrivKey.rsa.dq)
      deallocShared(certPrivKey.rsa.dp)
      deallocShared(certPrivKey.rsa.q)
      deallocShared(certPrivKey.rsa.p)
      zeroMem(certPrivKey.rsa, sizeof(br_rsa_private_key))
      deallocShared(certPrivKey.rsa)
      certPrivKey.rsa = nil
      certPrivKey = CertPrivateKey(keyType: CertPrivateKeyType.None)

  of CertPrivateKeyType.EC:
    if not certPrivKey.ec.isNil:
      zeroMem(certPrivKey.ec.x, certPrivKey.ec.xlen)
      deallocShared(certPrivKey.ec.x)
      zeroMem(certPrivKey.ec, sizeof(br_ec_private_key))
      deallocShared(certPrivKey.ec)
      certPrivKey.ec = nil
      certPrivKey = CertPrivateKey(keyType: CertPrivateKeyType.None)

  of CertPrivateKeyType.None:
    discard

proc loadKey*(keyFilePath: string = "privkey.pem"): WebPushKeyPair =
  var pemData: string
  try:
    pemData = readFile(keyFilePath)
  except:
    return
  var pemObjs = decodePem(pemData)
  for pemObj in pemObjs:
    if pemObj.name == "EC PRIVATE KEY":
      var privObj = decodeCertPrivateKey(pemObj.data)
      doAssert privObj.ec.xlen == WebPushPrvKeyLen
      var impl: ptr br_ec_impl = br_ec_get_default()
      var pk: br_ec_public_key
      var kbuf_pub: array[BR_EC_KBUF_PUB_MAX_SIZE, uint8]
      var pubLen = br_ec_compute_pub(impl, addr pk, addr kbuf_pub, privObj.ec)
      doAssert pubLen == WebPushPubKeyLen
      result.prv = privObj.ec.x.toBytes(privObj.ec.xlen)
      result.pub = pk.q.toBytes(pk.qlen)
      result.sk = br_ec_private_key(curve: privObj.ec.curve, x: addr result.prv[0], xlen: privObj.ec.xlen)
      result.pk = br_ec_public_key(curve: pk.curve, q: addr result.pub[0], qlen: pk.qlen)
      freeCertPrivateKey(privObj)
      break
  clearPemObjs(pemObjs)

proc isValid*(pair: var WebPushKeyPair): bool =
  (pair.prv.len == WebPushPrvKeyLen and pair.pub.len == WebPushPubKeyLen)


when isMainModule:
  var pair = loadKey()
  if not pair.isValid():
    pair = genKey()
    pair.save()
  echo "prv: ", pair.prv
  echo "pub: ", pair.pub
  pair.clear()
