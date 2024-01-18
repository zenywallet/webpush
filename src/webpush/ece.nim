# https://github.com/web-push-libs/ecec
# include/ece.h

type
  uint8_t = uint8
  uint32_t = uint32

const
  ECE_SALT_LENGTH* = 16
  ECE_TAG_LENGTH* = 16
  ECE_WEBPUSH_PRIVATE_KEY_LENGTH* = 32
  ECE_WEBPUSH_PUBLIC_KEY_LENGTH* = 65
  ECE_WEBPUSH_AUTH_SECRET_LENGTH* = 16
  ECE_WEBPUSH_DEFAULT_RS* = 4096
  ECE_AES128GCM_MIN_RS* = 18
  ECE_AES128GCM_HEADER_LENGTH* = 21
  ECE_AES128GCM_MAX_KEY_ID_LENGTH* = 255
  ECE_AES128GCM_PAD_SIZE* = 1
  ECE_AESGCM_MIN_RS* = 3
  ECE_AESGCM_PAD_SIZE* = 2
  ECE_OK* = 0
  ECE_ERROR_OUT_OF_MEMORY* = -1
  ECE_ERROR_INVALID_PRIVATE_KEY* = -2
  ECE_ERROR_INVALID_PUBLIC_KEY* = -3
  ECE_ERROR_COMPUTE_SECRET* = -4
  ECE_ERROR_ENCODE_PUBLIC_KEY* = -5
  ECE_ERROR_DECRYPT* = -6
  ECE_ERROR_DECRYPT_PADDING* = -7
  ECE_ERROR_ZERO_PLAINTEXT* = -8
  ECE_ERROR_SHORT_BLOCK* = -9
  ECE_ERROR_SHORT_HEADER* = -10
  ECE_ERROR_ZERO_CIPHERTEXT* = -11
  ECE_ERROR_HKDF* = -12
  ECE_ERROR_INVALID_ENCRYPTION_HEADER* = -13
  ECE_ERROR_INVALID_CRYPTO_KEY_HEADER* = -14
  ECE_ERROR_INVALID_RS* = -15
  ECE_ERROR_INVALID_SALT* = -16
  ECE_ERROR_INVALID_DH* = -17
  ECE_ERROR_ENCRYPT* = -18
  ECE_ERROR_ENCRYPT_PADDING* = -19
  ECE_ERROR_INVALID_AUTH_SECRET* = -20
  ECE_ERROR_GENERATE_KEYS* = -21
  ECE_ERROR_DECRYPT_TRUNCATED* = -22

##  Annotates a variable or parameter as unused to avoid compiler warnings.

template ECE_UNUSED*(x: untyped): untyped =
  (void)(x)

## !
##  The policy for appending trailing "=" characters to Base64url-encoded output.
##

type                          ## ! Omits padding, even if the input is not a multiple of 4.
  ece_base64url_encode_policy_t* = enum
    ECE_BASE64URL_OMIT_PADDING, ## ! Includes padding if the input is not a multiple of 4.
    ECE_BASE64URL_INCLUDE_PADDING


## !
##  The policy for handling trailing "=" characters in Base64url-encoded input.
##

type ## !
    ##  Fails decoding if the input is unpadded. RFC 4648, section 3.2 requires
    ##  padding, unless the referring specification prohibits it.
    ##
  ece_base64url_decode_policy_t* = enum
    ECE_BASE64URL_REQUIRE_PADDING, ## ! Tolerates padded and unpadded input.
    ECE_BASE64URL_IGNORE_PADDING, ## !
                                 ##  Fails decoding if the input is padded. This follows the strict Base64url
                                 ##  variant used in JWS (RFC 7515, Appendix C) and
                                 ##  draft-ietf-httpbis-encryption-encoding-03.
    ECE_BASE64URL_REJECT_PADDING


## !
##  Generates a public-private ECDH key pair and authentication secret for a Web
##  Push subscription.
##
##  \sa                          ece_webpush_aes128gcm_decrypt(),
##                               ece_webpush_aesgcm_decrypt()
##
##  \param rawRecvPrivKey[in]    The subscription private key. This key should
##                               be stored locally, and used to decrypt incoming
##                               messages.
##  \param rawRecvPrivKeyLen[in] The length of the subscription private key. Must
##                               be `ECE_WEBPUSH_PRIVATE_KEY_LENGTH`.
##  \param rawRecvPubKey[in]     The subscription public key, in uncompressed
##                               form. This key should be shared with the app
##                               server, and used to encrypt outgoing messages.
##  \param rawRecvPubKeyLen[in]  The length of the subscription public key. Must
##                               be `ECE_WEBPUSH_PUBLIC_KEY_LENGTH`.
##  \param authSecret[in]        The authentication secret. This secret should
##                               be stored locally and shared with the app
##                               server. It's used to derive the content
##                               encryption key and nonce.
##  \param authSecretLen[in]     The length of the authentication secret. Must
##                               be `ECE_WEBPUSH_AUTH_SECRET_LENGTH`.
##
##  \return                      `ECE_OK` on success, or an error code if key
##                               generation fails.
##

proc ece_webpush_generate_keys*(rawRecvPrivKey: ptr uint8_t;
                               rawRecvPrivKeyLen: csize_t;
                               rawRecvPubKey: ptr uint8_t;
                               rawRecvPubKeyLen: csize_t; authSecret: ptr uint8_t;
                               authSecretLen: csize_t): cint {.importc, cdecl.}
## !
##  Calculates the maximum "aes128gcm" plaintext length. The caller should
##  allocate and pass an array of this length to the "aes128gcm" decryption
##  functions.
##
##  \sa                   ece_aes128gcm_decrypt(),
##                        ece_webpush_aes128gcm_decrypt()
##
##  \param payload[in]    The encrypted payload.
##  \param payloadLen[in] The length of the encrypted payload.
##
##  \return               The maximum plaintext length, or 0 if the payload
##                        header is truncated or invalid.
##

proc ece_aes128gcm_plaintext_max_length*(payload: ptr uint8_t; payloadLen: csize_t): csize_t {.importc, cdecl.}
## !
##  Decrypts a message encrypted using the "aes128gcm" scheme, with a symmetric
##  key. The key is shared out of band, and identified by the `keyId` parameter
##  in the payload header.
##
##  \sa                          ece_aes128gcm_plaintext_max_length(),
##                               ece_aes128gcm_payload_extract_params()
##
##  \param ikm[in]               The input keying material (IKM) for the content
##                               encryption key and nonce.
##  \param ikmLen[in]            The length of the IKM.
##  \param payload[in]           The encrypted payload.
##  \param payloadLen[in]        The length of the encrypted payload.
##  \param plaintext[in]         An empty array. Must be large enough to hold the
##                               full plaintext.
##  \param plaintextLen[in,out]  The input is the length of the empty `plaintext`
##                               array. On success, the output is set to the
##                               actual plaintext length, and
##                               `[0..plaintextLen]` contains the plaintext.
##
##  \return                      `ECE_OK` on success, or an error code if
##                               the payload is empty or malformed.
##

proc ece_aes128gcm_decrypt*(ikm: ptr uint8_t; ikmLen: csize_t; payload: ptr uint8_t;
                           payloadLen: csize_t; plaintext: ptr uint8_t;
                           plaintextLen: ptr csize_t): cint {.importc, cdecl.}
## !
##  Decrypts a Web Push message encrypted using the "aes128gcm" scheme.
##
##  \sa                          ece_aes128gcm_plaintext_max_length()
##
##  \param rawRecvPrivKey[in]    The subscription private key.
##  \param rawRecvPrivKeyLen[in] The length of the subscription private key. Must
##                               be `ECE_WEBPUSH_PRIVATE_KEY_LENGTH`.
##  \param authSecret[in]        The authentication secret.
##  \param authSecretLen[in]     The length of the authentication secret. Must be
##                               `ECE_WEBPUSH_AUTH_SECRET_LENGTH`.
##  \param payload[in]           The encrypted payload.
##  \param payloadLen[in]        The length of the encrypted payload.
##  \param plaintext[in]         An empty array. Must be large enough to hold the
##                               full plaintext.
##  \param plaintextLen[in,out]  The input is the length of the empty `plaintext`
##                               array. On success, the output is set to the
##                               the actual plaintext length, and
##                               `[0..plaintextLen]` contains the plaintext.
##
##  \return                      `ECE_OK` on success, or an error code if
##                               the payload is empty or malformed.
##

proc ece_webpush_aes128gcm_decrypt*(rawRecvPrivKey: ptr uint8_t;
                                   rawRecvPrivKeyLen: csize_t;
                                   authSecret: ptr uint8_t; authSecretLen: csize_t;
                                   payload: ptr uint8_t; payloadLen: csize_t;
                                   plaintext: ptr uint8_t;
                                   plaintextLen: ptr csize_t): cint {.importc, cdecl.}
## !
##  Calculates the maximum "aes128gcm" encrypted payload length. The caller
##  should allocate and pass an array of this length to the "aes128gcm"
##  encryption functions.
##
##  \param rs[in]           The record size. This is the length of each encrypted
##                          plaintext chunk, including room for the padding
##                          delimiter and GCM authentication tag. Must be at
##                          least `ECE_AES128GCM_MIN_RS`.
##  \param padLen[in]       The length of additional padding, used to hide the
##                          plaintext length. Padding is added to the plaintext
##                          during encryption, and discarded during decryption.
##  \param plaintextLen[in] The length of the plaintext.
##
##  \return                 The maximum payload length, or 0 if `rs` is too
##                          small.
##

proc ece_aes128gcm_payload_max_length*(rs: uint32_t; padLen: csize_t;
                                      plaintextLen: csize_t): csize_t {.importc, cdecl.}
## !
##  Encrypts a Web Push message using the "aes128gcm" scheme. This function
##  automatically generates an ephemeral ECDH key pair and a random salt.
##
##  \sa                         ece_aes128gcm_payload_max_length()
##
##  \param rawRecvPubKey[in]    The subscription public key, in uncompressed
##                              form.
##  \param rawRecvPubKeyLen[in] The length of the subscription public key. Must
##                              be `ECE_WEBPUSH_PUBLIC_KEY_LENGTH`.
##  \param authSecret[in]       The authentication secret.
##  \param authSecretLen[in]    The length of the authentication secret. Must be
##                              `ECE_WEBPUSH_AUTH_SECRET_LENGTH`.
##  \param rs[in]               The record size. Must be at least
##                              `ECE_AES128GCM_MIN_RS`.
##  \param padLen[in]           The length of additional padding to include in
##                              the ciphertext, if any.
##  \param plaintext[in]        The plaintext to encrypt.
##  \param plaintextLen[in]     The length of the plaintext.
##  \param payload[in]          An empty array. Must be large enough to hold the
##                              full payload.
##  \param payloadLen[in,out]   The input is the length of the empty `payload`
##                              array. On success, the output is set to the
##                              actual payload length, and
##                              `payload[0..payloadLen]` contains the payload.
##
##  \return                     `ECE_OK` on success, or an error code if
##                              encryption fails.
##

proc ece_webpush_aes128gcm_encrypt*(rawRecvPubKey: ptr uint8_t;
                                   rawRecvPubKeyLen: csize_t;
                                   authSecret: ptr uint8_t; authSecretLen: csize_t;
                                   rs: uint32_t; padLen: csize_t;
                                   plaintext: ptr uint8_t; plaintextLen: csize_t;
                                   payload: ptr uint8_t; payloadLen: ptr csize_t): cint {.importc, cdecl.}
## !
##  Encrypts a Web Push message using the "aes128gcm" scheme, with an explicit
##  sender key and salt. The sender key can be reused, but the salt *must* be
##  unique to avoid deriving the same content encryption key for multiple
##  messages.
##
##  \warning                       In general, you should only use this function
##                                 for testing. `ece_webpush_aes128gcm_encrypt`
##                                 is safer because it doesn't risk accidental
##                                 salt reuse.
##
##  \sa                            ece_aes128gcm_payload_max_length(),
##                                 ece_webpush_aes128gcm_encrypt()
##
##  \param rawSenderPrivKey[in]    The sender private key.
##  \param rawSenderPrivKeyLen[in] The length of the sender private key. Must be
##                                 `ECE_WEBPUSH_PRIVATE_KEY_LENGTH`.
##  \param authSecret[in]          The authentication secret.
##  \param authSecretLen[in]       The length of the authentication secret. Must
##                                 be `ECE_WEBPUSH_AUTH_SECRET_LENGTH`.
##  \param salt[in]                The encryption salt.
##  \param saltLen[in]             The length of the salt. Must be
##                                 `ECE_SALT_LENGTH`.
##  \param rawRecvPubKey[in]       The subscription public key, in uncompressed
##                                 form. Must be `ECE_WEBPUSH_PUBLIC_KEY_LENGTH`.
##  \param rawRecvPubKeyLen[in]    The length of the subscription public key.
##  \param rs[in]                  The record size. Must be at least
##                                 `ECE_AES128GCM_MIN_RS`.
##  \param padLen[in]              The length of additional padding to include in
##                                 the ciphertext, if any.
##  \param plaintext[in]           The plaintext to encrypt.
##  \param plaintextLen[in]        The length of the plaintext.
##  \param payload[in]             An empty array. Must be large enough to hold
##                                 the full payload.
##  \param payloadLen[in,out]      The input is the length of the empty `payload`
##                                 array. On success, the output is set to the
##                                 actual payload length, and
##                                 `payload[0..payloadLen]` contains the payload.
##
##  \return                        `ECE_OK` on success, or an error code if
##                                 encryption fails.
##

proc ece_webpush_aes128gcm_encrypt_with_keys*(rawSenderPrivKey: ptr uint8_t;
    rawSenderPrivKeyLen: csize_t; authSecret: ptr uint8_t; authSecretLen: csize_t;
    salt: ptr uint8_t; saltLen: csize_t; rawRecvPubKey: ptr uint8_t;
    rawRecvPubKeyLen: csize_t; rs: uint32_t; padLen: csize_t; plaintext: ptr uint8_t;
    plaintextLen: csize_t; payload: ptr uint8_t; payloadLen: ptr csize_t): cint {.importc, cdecl.}
## !
##  Calculates the maximum "aesgcm" ciphertext length. The caller should allocate
##  and pass an array of this length to `ece_webpush_aesgcm_encrypt_with_keys`.
##
##  \param rs[in]           The record size. Must be least `ECE_AESGCM_MIN_RS`.
##  \param padLen[in]       The length of additional padding.
##  \param plaintextLen[in] The length of the plaintext.
##
##  \return                 The maximum ciphertext length, or 0 if `rs` is too
##                          small.
##

proc ece_aesgcm_ciphertext_max_length*(rs: uint32_t; padLen: csize_t;
                                      plaintextLen: csize_t): csize_t {.importc, cdecl.}
## !
##  Encrypts a Web Push message using the "aesgcm" scheme. Like
##  `ece_webpush_aes128gcm_encrypt`, this function generates a sender key pair
##  and salt.
##
##  \sa                           ece_aesgcm_ciphertext_max_length()
##
##  \param rawRecvPubKey[in]      The subscription public key, in uncompressed
##                                form.
##  \param rawRecvPubKeyLen[in]   The length of the subscription public key. Must
##                                be `ECE_WEBPUSH_PUBLIC_KEY_LENGTH`.
##  \param authSecret[in]         The authentication secret.
##  \param authSecretLen[in]      The length of the authentication secret. Must
##                                be `ECE_WEBPUSH_AUTH_SECRET_LENGTH`.
##  \param rs[in]                 The record size. Must be at least
##                                `ECE_AES128GCM_MIN_RS`.
##  \param padLen[in]             The length of additional padding to include in
##                                the ciphertext, if any.
##  \param plaintext[in]          The plaintext to encrypt.
##  \param plaintextLen[in]       The length of the plaintext.
##  \param salt[in]               An empty array to hold the salt.
##  \param saltLen[in]            The length of the empty `salt` array. Must be
##                                `ECE_SALT_LENGTH`.
##  \param rawSenderPubKey[in]    An empty array to hold the sender public key.
##  \param rawSenderPubKeyLen[in] The length of the empty `rawSenderPubKey`
##                                array. Must be `ECE_WEBPUSH_PUBLIC_KEY_LENGTH`.
##  \param ciphertext[in]         An empty array to hold the ciphertext.
##  \param ciphertextLen[in, out] The input is the length of the empty
##                                `ciphertext` array. On success, the output is
##                                set to the actual ciphertext length, and
##                                `ciphertext[0..ciphertextLen]` contains the
##                                ciphertext.
##
##  \return                       `ECE_OK` on success, or an error code if
##                                encryption fails.
##

proc ece_webpush_aesgcm_encrypt*(rawRecvPubKey: ptr uint8_t;
                                rawRecvPubKeyLen: csize_t;
                                authSecret: ptr uint8_t; authSecretLen: csize_t;
                                rs: uint32_t; padLen: csize_t;
                                plaintext: ptr uint8_t; plaintextLen: csize_t;
                                salt: ptr uint8_t; saltLen: csize_t;
                                rawSenderPubKey: ptr uint8_t;
                                rawSenderPubKeyLen: csize_t;
                                ciphertext: ptr uint8_t; ciphertextLen: ptr csize_t): cint {.importc, cdecl.}
## !
##  Encrypts a Web Push message using the "aesgcm" scheme and explicit keys.
##
##  \warning                       `ece_webpush_aesgcm_encrypt` is safer because
##                                 it doesn't risk accidental salt reuse.
##
##  \sa                            ece_aesgcm_ciphertext_max_length(),
##                                 ece_webpush_aesgcm_encrypt()
##
##  \param rawSenderPrivKey[in]    The sender private key.
##  \param rawSenderPrivKeyLen[in] The length of the sender private key. Must be
##                                 `ECE_WEBPUSH_PRIVATE_KEY_LENGTH`.
##  \param authSecret[in]          The authentication secret.
##  \param authSecretLen[in]       The length of the authentication secret. Must
##                                 be `ECE_WEBPUSH_AUTH_SECRET_LENGTH`.
##  \param salt[in]                The encryption salt.
##  \param saltLen[in]             The length of the salt. Must be
##                                 `ECE_SALT_LENGTH`.
##  \param rawRecvPubKey[in]       The subscription public key, in uncompressed
##                                 form. Must be `ECE_WEBPUSH_PUBLIC_KEY_LENGTH`.
##  \param rawRecvPubKeyLen[in]    The length of the subscription public key.
##  \param rs[in]                  The record size. Must be at least
##                                 `ECE_AES128GCM_MIN_RS`.
##  \param padLen[in]              The length of additional padding to include in
##                                 the ciphertext, if any.
##  \param plaintext[in]           The plaintext to encrypt.
##  \param plaintextLen[in]        The length of the plaintext.
##  \param rawSenderPubKey[in]     An empty array to hold the sender public key,
##                                 in uncompressed form, to include in the
##                                 `Crypto-Key` header.
##  \param rawSenderPubKeyLen[in]  The length of the empty `rawSenderPubKey`
##                                 array. Must be
##                                 `ECE_WEBPUSH_PUBLIC_KEY_LENGTH`.
##  \param ciphertext[in]          An empty array. Must be large enough to hold
##                                 the full ciphertext.
##  \param ciphertextLen[in,out]   The input is the length of the empty
##                                 `ciphertext` array. On success, the output is
##                                 set to the actual ciphertext length, and
##                                 `ciphertext[0..ciphertextLen]` contains the
##                                 ciphertext.
##
##  \return                        `ECE_OK` on success, or an error code if
##                                 encryption fails.
##

proc ece_webpush_aesgcm_encrypt_with_keys*(rawSenderPrivKey: ptr uint8_t;
    rawSenderPrivKeyLen: csize_t; authSecret: ptr uint8_t; authSecretLen: csize_t;
    salt: ptr uint8_t; saltLen: csize_t; rawRecvPubKey: ptr uint8_t;
    rawRecvPubKeyLen: csize_t; rs: uint32_t; padLen: csize_t; plaintext: ptr uint8_t;
    plaintextLen: csize_t; rawSenderPubKey: ptr uint8_t; rawSenderPubKeyLen: csize_t;
    ciphertext: ptr uint8_t; ciphertextLen: ptr csize_t): cint {.importc, cdecl.}
## !
##  Calculates the maximum "aesgcm" plaintext length. The caller should allocate
##  and pass an array of this length to `ece_webpush_aesgcm_decrypt`.
##
##  \sa                      ece_webpush_aesgcm_decrypt()
##
##  \param rs[in]            The record size. Must be at least
##                           `ECE_AESGCM_MIN_RS`.
##  \param ciphertextLen[in] The ciphertext length.
##
##  \return                  The maximum plaintext length.
##

proc ece_aesgcm_plaintext_max_length*(rs: uint32_t; ciphertextLen: csize_t): csize_t {.importc, cdecl.}
## !
##  Decrypts a Web Push message encrypted using the "aesgcm" scheme.
##
##  \sa                           ece_aesgcm_plaintext_max_length()
##
##  \param rawRecvPrivKey[in]     The subscription private key.
##  \param rawRecvPrivKeyLen[in]  The length of the subscription private key.
##                                Must be `ECE_WEBPUSH_PRIVATE_KEY_LENGTH`.
##  \param authSecret[in]         The authentication secret.
##  \param authSecretLen[in]      The length of the authentication secret. Must
##                                be `ECE_WEBPUSH_AUTH_SECRET_LENGTH`.
##  \param salt[in]
##  \param salt[in]               The salt, from the `Encryption` header.
##  \param saltLen[in]            The length of the salt. Must be
##                                `ECE_SALT_LENGTH`.
##  \param rawSenderPubKey[in]    The sender public key, in uncompressed form,
##                                from the `Crypto-Key` header.
##  \param rawSenderPubKeyLen[in] The length of the sender public key. Must be
##                                `ECE_WEBPUSH_PUBLIC_KEY_LENGTH`.
##  \param rs[in]                 The record size. Must be at least
##                                `ECE_AESGCM_MIN_RS`.
##  \param ciphertext[in]         The ciphertext.
##  \param ciphertextLen[in]      The length of the ciphertext.
##  \param plaintext[in]          An empty array. Must be large enough to hold
##                                the full plaintext.
##  \param plaintextLen[in,out]   The input is the length of the empty
##                                `plaintext` array. On success, the output is
##                                set to the actual plaintext length, and
##                                `[0..plaintextLen]` contains the plaintext.
##
##  \return                       `ECE_OK` on success, or an error code if the
##                                headers or ciphertext are malformed.
##

proc ece_webpush_aesgcm_decrypt*(rawRecvPrivKey: ptr uint8_t;
                                rawRecvPrivKeyLen: csize_t;
                                authSecret: ptr uint8_t; authSecretLen: csize_t;
                                salt: ptr uint8_t; saltLen: csize_t;
                                rawSenderPubKey: ptr uint8_t;
                                rawSenderPubKeyLen: csize_t; rs: uint32_t;
                                ciphertext: ptr uint8_t; ciphertextLen: csize_t;
                                plaintext: ptr uint8_t; plaintextLen: ptr csize_t): cint {.importc, cdecl.}
## !
##  Extracts "aes128gcm" decryption parameters from an encrypted payload.
##  `salt`, `keyId`, and `ciphertext` are pointers into `payload`, and must not
##  outlive it.
##
##  \sa                       ece_aes128gcm_decrypt()
##
##  \param payload[in]        The encrypted payload.
##  \param payloadLen[in]     The length of the encrypted payload.
##  \param salt[out]          The encryption salt.
##  \param saltLen[out]       The length of the salt.
##  \param keyId[out]         An identifier for the keying material.
##  \param keyIdLen[out]      The length of the key ID.
##  \param rs[out]            The record size.
##  \param ciphertext[out]    The ciphertext.
##  \param ciphertextLen[out] The length of the ciphertext.
##
##  \return                   `ECE_OK` on success, or an error code if the
##                            payload header is truncated or invalid.
##

proc ece_aes128gcm_payload_extract_params*(payload: ptr uint8_t;
    payloadLen: csize_t; salt: ptr ptr uint8_t; saltLen: ptr csize_t;
    keyId: ptr ptr uint8_t; keyIdLen: ptr csize_t; rs: ptr uint32_t;
    ciphertext: ptr ptr uint8_t; ciphertextLen: ptr csize_t): cint {.importc, cdecl.}
## !
##  Extracts "aesgcm" decryption parameters from the `Crypto-Key` and
##  `Encryption` headers.
##
##  \sa                           ece_webpush_aesgcm_decrypt(),
##                                ece_webpush_aesgcm_headers_from_params()
##
##  \param cryptoKeyHeader[in]    The value of the `Crypto-Key` HTTP header.
##  \param encryptionHeader[in]   The value of the `Encryption` HTTP header.
##  \param salt[in]               An empty array to hold the encryption salt,
##                                extracted from the `Encryption` header.
##  \param saltLen[in]            The length of the empty `salt` array. Must be
##                                `ECE_SALT_LENGTH`.
##  \param rawSenderPubKey[in]    An empty array to hold the sender public key,
##                                in uncompressed form, extracted from the
##                                `Crypto-Key` header.
##  \param rawSenderPubKeyLen[in] The length of the empty `rawSenderPubKey`
##                                array. Must be `ECE_WEBPUSH_PUBLIC_KEY_LENGTH`.
##  \param rs[out]                The record size.
##
##  \return                       `ECE_OK` on success, or an error code if the
##                                headers are malformed.
##

proc ece_webpush_aesgcm_headers_extract_params*(cryptoKeyHeader: cstring;
    encryptionHeader: cstring; salt: ptr uint8_t; saltLen: csize_t;
    rawSenderPubKey: ptr uint8_t; rawSenderPubKeyLen: csize_t; rs: ptr uint32_t): cint {.importc, cdecl.}
## !
##  Builds the `Crypto-Key` and `Encryption` headers from the "aesgcm"
##  encryption parameters.
##
##  \sa                               ece_webpush_aesgcm_encrypt_with_keys(),
##                                    ece_webpush_aesgcm_headers_extract_params()
##
##  \param salt[in]                     The encryption salt, to include in the
##                                      `Encryption` header.
##  \param saltLen[in]                  The length of the salt. Must be
##                                      `ECE_SALT_LENGTH`.
##  \param rawSenderPubKey[in]          The sender public key, in uncompressed
##                                      form, to include in the `Crypto-Key`
##                                      header.
##  \param rawSenderPubKeyLen[in]       The length of the sender public key. Must
##                                      be `ECE_WEBPUSH_PUBLIC_KEY_LENGTH`.
##  \param rs[in]                       The record size, to include in the
##                                      `Encryption` header.
##  \param cryptoKeyHeader[in]          An empty array to hold the `Crypto-Key`
##                                      header. May be `NULL` if
##                                      `cryptoKeyHeaderLen` is 0. The header is
##                                      *not* null-terminated; you'll need to add
##                                      a trailing `'\0'` if you want to treat
##                                      `cryptoKeyHeader` as a C string.
##  \param cryptoKeyHeaderLen[in, out]  The input is the length of the empty
##                                      `cryptoKeyHeader` array. If 0, the output
##                                      is set to the length required to hold
##                                      the result. On success,
##                                      `[0..cryptoKeyHeaderLen]` contains the
##                                      header.
##  \param encryptionHeader[in]         An empty array to hold the `Encryption`
##                                      header. May be `NULL` if
##                                      `encryptionHeaderLen` is 0. Like
##                                      `cryptoKeyHeader`, this header is not
##                                      null-terminated.
##  \param encryptionHeaderLen[in, out] The input is the length of the empty
##                                      `encryptionHeader` array. If 0, the
##                                      output is set to the length required to
##                                      hold the result. On success,
##                                      `[0..encryptionHeaderLen]` contains the
##                                      header.
##
##  \return                             `ECE_OK` on success, or an error code if
##                                      `cryptoKeyHeaderLen` or
##                                      `encryptionHeaderLen` is too small.
##

proc ece_webpush_aesgcm_headers_from_params*(salt: pointer; saltLen: csize_t;
    rawSenderPubKey: pointer; rawSenderPubKeyLen: csize_t; rs: uint32_t;
    cryptoKeyHeader: cstring; cryptoKeyHeaderLen: ptr csize_t;
    encryptionHeader: cstring; encryptionHeaderLen: ptr csize_t): cint {.importc, cdecl.}
## !
##  Converts a byte array to a Base64url-encoded (RFC 4648) string.
##
##  \param binary[in]        The byte array to encode.
##  \param binaryLen[in]     The length of the byte array.
##  \param paddingPolicy[in] The policy for padding the encoded output.
##  \param base64[in]        An empty array to hold the encoded result. May be
##                           `NULL` if `base64Len` is 0. This function does
##                           *not* null-terminate `base64`. This makes it easier
##                           to include Base64url-encoded substrings in larger
##                           strings, but means you'll need to add a trailing
##                           `'\0'` if you want to treat `base64` as a C string.
##  \param base64Len[in]     The length of the empty `base64` array. On success,
##                           `base64[0..base64Len]` contains the result.
##
##  \return                  The encoded length. If `binaryLen` is 0, returns the
##                           length of the array required to hold the result. If
##                           `binaryLen` is not large enough to hold the full
##                           result, returns 0.
##

proc ece_base64url_encode*(binary: pointer; binaryLen: csize_t;
                          paddingPolicy: ece_base64url_encode_policy_t;
                          base64: cstring; base64Len: csize_t): csize_t {.importc, cdecl.}
## !
##  Decodes a Base64url-encoded (RFC 4648) string.
##
##  \param base64[in]        The encoded string.
##  \param base64Len[in]     The length of the encoded string.
##  \param paddingPolicy[in] The policy for handling "=" padding in the encoded
##                           input.
##  \param binary[in]        An empty array to hold the decoded result. May be
##                           `NULL` if `binaryLen` is 0.
##  \param binaryLen[in]     The length of the empty `binary` array. On success,
##                           `binary[0..binaryLen]` contains the result.
##
##  \return                  The actual decoded length. If `binaryLen` is 0,
##                           returns the length of the array
##                           required to hold the result. If `base64` contains
##                           invalid characters, or `binaryLen` is not large
##                           enough to hold the full result, returns 0.
##

proc ece_base64url_decode*(base64: cstring; base64Len: csize_t;
                          paddingPolicy: ece_base64url_decode_policy_t;
                          binary: ptr uint8_t; binaryLen: csize_t): csize_t {.importc, cdecl.}


import os
const libecePath = currentSourcePath.parentDir() / "./lib"
{.passL: libecePath / "libece.a".}
