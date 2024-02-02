# https://github.com/web-push-libs/ecec
# include/ece/keys.h

# openssl ec.h
type
  ec_key_st* = ptr object
  EC_KEY* = ec_key_st

type
  uint8_t = uint8
  uint64_t = uint64

const
  ECE_AES_KEY_LENGTH* = 16
  ECE_NONCE_LENGTH* = 12
  ECE_WEBPUSH_IKM_LENGTH* = 32

##  HKDF info strings for the "aes128gcm" scheme. Note that the lengths include
##  the NUL terminator.

const
  ECE_WEBPUSH_AES128GCM_IKM_INFO_PREFIX* = "WebPush: info\x00"
  ECE_WEBPUSH_AES128GCM_IKM_INFO_PREFIX_LENGTH* = 14
  ECE_WEBPUSH_AES128GCM_IKM_INFO_LENGTH* = 144
  ECE_AES128GCM_KEY_INFO* = "Content-Encoding: aes128gcm\x00"
  ECE_AES128GCM_KEY_INFO_LENGTH* = 28
  ECE_AES128GCM_NONCE_INFO* = "Content-Encoding: nonce\x00"
  ECE_AES128GCM_NONCE_INFO_LENGTH* = 24

##  HKDF info strings for the "aesgcm" scheme.

const
  ECE_WEBPUSH_AESGCM_IKM_INFO* = "Content-Encoding: auth\x00"
  ECE_WEBPUSH_AESGCM_IKM_INFO_LENGTH* = 23
  ECE_WEBPUSH_AESGCM_KEY_INFO_PREFIX* = "Content-Encoding: aesgcm\x00P-256\x00"
  ECE_WEBPUSH_AESGCM_KEY_INFO_PREFIX_LENGTH* = 31
  ECE_WEBPUSH_AESGCM_KEY_INFO_LENGTH* = 165
  ECE_WEBPUSH_AESGCM_NONCE_INFO_PREFIX* = "Content-Encoding: nonce\x00P-256\x00"
  ECE_WEBPUSH_AESGCM_NONCE_INFO_PREFIX_LENGTH* = 30
  ECE_WEBPUSH_AESGCM_NONCE_INFO_LENGTH* = 164

##  Key derivation modes.

type
  ece_mode_t* = enum
    ECE_MODE_ENCRYPT, ECE_MODE_DECRYPT
  derive_key_and_nonce_t* = proc (mode: ece_mode_t; localKey: EC_KEY;
                               remoteKey: EC_KEY; authSecret: ptr uint8_t;
                               authSecretLen: csize_t; salt: ptr uint8_t;
                               saltLen: csize_t; key: ptr uint8_t; nonce: ptr uint8_t): cint {.cdecl.}


##  Generates a 96-bit IV for decryption, 48 bits of which are populated.

proc ece_generate_iv*(nonce: ptr uint8_t; counter: uint64_t; iv: ptr uint8_t) {.importc, cdecl.}
##  Inflates a raw ECDH private key into an OpenSSL `EC_KEY` containing a
##  private and public key pair. Returns `NULL` on error.

proc ece_import_private_key*(rawKey: ptr uint8_t; rawKeyLen: csize_t): EC_KEY {.importc, cdecl.}
##  Inflates a raw ECDH public key into an `EC_KEY` containing a public key.
##  Returns `NULL` on error.

proc ece_import_public_key*(rawKey: ptr uint8_t; rawKeyLen: csize_t): EC_KEY {.importc, cdecl.}
##  Derives the "aes128gcm" content encryption key and nonce.

proc ece_aes128gcm_derive_key_and_nonce*(salt: ptr uint8_t; saltLen: csize_t;
                                        ikm: ptr uint8_t; ikmLen: csize_t;
                                        key: ptr uint8_t; nonce: ptr uint8_t): cint {.importc, cdecl.}
##  Derives the "aes128gcm" decryption key and nonce given the receiver private
##  key, sender public key, authentication secret, and sender salt.

proc ece_webpush_aes128gcm_derive_key_and_nonce*(mode: ece_mode_t;
    localKey: EC_KEY; remoteKey: EC_KEY; authSecret: ptr uint8_t;
    authSecretLen: csize_t; salt: ptr uint8_t; saltLen: csize_t; key: ptr uint8_t;
    nonce: ptr uint8_t): cint {.importc, cdecl.}
##  Derives the "aesgcm" decryption key and nonce given the receiver private key,
##  sender public key, authentication secret, and sender salt.

proc ece_webpush_aesgcm_derive_key_and_nonce*(mode: ece_mode_t;
    recvPrivKey: EC_KEY; senderPubKey: EC_KEY; authSecret: ptr uint8_t;
    authSecretLen: csize_t; salt: ptr uint8_t; saltLen: csize_t; key: ptr uint8_t;
    nonce: ptr uint8_t): cint {.importc, cdecl.}
