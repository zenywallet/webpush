# Copyright (c) 2024 zenywallet

import std/base64
import std/json
import std/strutils
import std/times
import nimcrypto
import bytes

var jwsHeaderJson = %*{"typ":"JWT","alg":"ES256"}
var jwsPayloadJson = %*{"aud":"https://push.services.mozilla.com","sub":"mailto:admin@example.com","exp":int(epochTime() + 86400)}
echo jwsHeaderJson
echo jwsPayloadJson

var jwsHeader = base64.encode($jwsHeaderJson, true)
jwsHeader.removeSuffix('=')
var jwsPayload = base64.encode($jwsPayloadJson, true)
jwsPayload.removeSuffix('=')

var jwsSigningInput = jwsHeader & "." & jwsPayload

proc sha256s*(data: openarray[byte]): array[32, byte] {.inline.} =
  sha256.digest(data).data

echo sha256s(cast[seq[byte]](jwsSigningInput))


# include/openssl/obj_mac.h
const NID_X9_62_prime256v1* = 415

# include/openssl/types.h
type
  bignum_st = ptr object
  BIGNUM = bignum_st

# include/openssl/ec.h
type
  ec_key_st = ptr object
  EC_KEY = ec_key_st
  ec_group_st = ptr object
  EC_GROUP = ec_group_st
  ec_point_st = ptr object
  EC_POINT = ec_point_st
  bignum_ctx = ptr object
  BN_CTX = bignum_ctx

type
  point_conversion_form_t* = enum
    POINT_CONVERSION_COMPRESSED = 2
    POINT_CONVERSION_UNCOMPRESSED = 4
    POINT_CONVERSION_HYBRID = 6

proc EC_KEY_new_by_curve_name*(nid: cint): EC_KEY {.importc, cdecl.}
proc EC_KEY_free*(key: EC_KEY) {.importc, cdecl.}
proc EC_GROUP_new_by_curve_name*(nid: cint): EC_GROUP {.importc, cdecl.}
proc EC_POINT_point2oct*(group: EC_GROUP; p: EC_POINT;
                        form: point_conversion_form_t; buf: ptr cuchar;
                        len: csize_t; ctx: BN_CTX): csize_t {.importc, cdecl.}
proc EC_POINT_oct2point*(group: EC_GROUP; p: EC_POINT; buf: ptr cuchar;
                        len: csize_t; ctx: BN_CTX): cint {.importc, cdecl.}
proc EC_KEY_oct2priv*(key: EC_KEY; buf: ptr cuchar; len: csize_t): cint {.importc, cdecl.}
proc EC_KEY_priv2oct*(key: EC_KEY; buf: ptr cuchar; len: csize_t): csize_t {.importc, cdecl.}
proc EC_KEY_get0_group*(key: EC_KEY): EC_GROUP {.importc, cdecl.}
proc EC_KEY_get0_private_key*(key: EC_KEY): BIGNUM {.importc, cdecl.}
proc EC_KEY_set_private_key*(key: EC_KEY; prv: BIGNUM): cint {.importc, cdecl.}
proc EC_KEY_get0_public_key*(key: EC_KEY): EC_POINT {.importc, cdecl.}
proc EC_KEY_generate_key*(key: EC_KEY): cint {.importc, cdecl.}


import os
const opensslPath = currentSourcePath.parentDir() / "../lib/openssl"
{.passL: opensslPath / "libssl.a".}
{.passL: opensslPath / "libcrypto.a".}


var key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)
if key.isNil:
  raise

if EC_KEY_generate_key(key) != 1:
  EC_KEY_free(key)
  raise

import ece

var rawPrivKey: array[ECE_WEBPUSH_PRIVATE_KEY_LENGTH, byte]
if EC_KEY_priv2oct(key, cast[ptr cuchar](addr rawPrivKey), ECE_WEBPUSH_PRIVATE_KEY_LENGTH) == 0:
  raise
echo rawPrivKey

var key2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)
if EC_KEY_set_private_key(key2, EC_KEY_get0_private_key(key)) != 1:
  raise
var rawPrivKey2: array[ECE_WEBPUSH_PRIVATE_KEY_LENGTH, byte]
if EC_KEY_priv2oct(key2, cast[ptr cuchar](addr rawPrivKey2), ECE_WEBPUSH_PRIVATE_KEY_LENGTH) == 0:
  raise
echo rawPrivKey2

var key3 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)
if EC_KEY_oct2priv(key3, cast[ptr cuchar](addr rawPrivKey), ECE_WEBPUSH_PRIVATE_KEY_LENGTH) == 0:
  raise
var rawPrivKey3: array[ECE_WEBPUSH_PRIVATE_KEY_LENGTH, byte]
if EC_KEY_priv2oct(key3, cast[ptr cuchar](addr rawPrivKey3), ECE_WEBPUSH_PRIVATE_KEY_LENGTH) == 0:
  raise
echo rawPrivKey3


var rawPubKey: array[ECE_WEBPUSH_PUBLIC_KEY_LENGTH, byte]
if EC_POINT_point2oct(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key),
                      POINT_CONVERSION_UNCOMPRESSED, cast[ptr cuchar](addr rawPubKey),
                      ECE_WEBPUSH_PUBLIC_KEY_LENGTH, nil) == 0:
  raise
echo "rawPubKey=", rawPubKey


import webpush

const vapidKeyFile = currentSourcePath().parentDir() / "vapidKey.pem"
var pair = loadKey(vapidKeyFile)
if not pair.isValid():
  pair = genKey()
  pair.save(vapidKeyFile)

echo pair


var key4 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)
if EC_KEY_oct2priv(key4, cast[ptr cuchar](addr pair.prv[0]), ECE_WEBPUSH_PRIVATE_KEY_LENGTH) == 0:
  raise
var rawPrivKey4: array[ECE_WEBPUSH_PRIVATE_KEY_LENGTH, byte]
if EC_KEY_priv2oct(key4, cast[ptr cuchar](addr rawPrivKey4), ECE_WEBPUSH_PRIVATE_KEY_LENGTH) == 0:
  raise
echo rawPrivKey4

#[
var rawPubKey2: array[ECE_WEBPUSH_PUBLIC_KEY_LENGTH, byte]
if EC_POINT_point2oct(EC_KEY_get0_group(key4), EC_KEY_get0_public_key(key4),
                      POINT_CONVERSION_UNCOMPRESSED, cast[ptr cuchar](addr rawPubKey2),
                      ECE_WEBPUSH_PUBLIC_KEY_LENGTH, nil) == 0:
  raise
echo "rawPubKey2=", rawPubKey2
]#

import bearssl/bearssl_ssl
import bearssl/bearssl_rsa
import bearssl/bearssl_ec
import bearssl/bearssl_rand
import bearssl/bearssl_hash
import bearssl/bearssl_x509
import bearssl/bearssl_pem

var impl: ptr br_ec_impl = br_ec_get_default()
var sk: br_ec_private_key = br_ec_private_key(curve: BR_EC_secp256r1, x: addr rawPrivKey[0], xlen: rawPrivKey.len.csize_t)
var pk: br_ec_public_key
var kbuf_pub: array[BR_EC_KBUF_PUB_MAX_SIZE, uint8]
var pubLen = br_ec_compute_pub(impl, addr pk, addr kbuf_pub, addr sk) #privObj.ec)
echo "ECE_WEBPUSH_PRIVATE_KEY_LENGTH=", ECE_WEBPUSH_PRIVATE_KEY_LENGTH
echo "rawPrivKey=", rawPrivKey
echo "pubLen=", pubLen
echo "kbuf_pub=", kbuf_pub[0..<pubLen]
