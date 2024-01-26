# Copyright (c) 2024 zenywallet

import ece
import bytes

const endpoint = "https://updates.push.services.mozilla.com/..."
const p256dh = "BDwwYm4O5dZG9SO6Vaz168iDLGWMmitkj5LFvunvMfgmI2fZdAEaiHT" &
                "DfKR0fvr0D3V56cSGSeUwP0xNdrXho5k"
const auth = "xcmQLthL5H2pJNuxrZO-qQ"
const plaintext = "I'm just like my country, I'm young, scrappy, and " &
                  "hungry, and I'm not throwing away my shot."

var rawRecvPubKey: array[ECE_WEBPUSH_PUBLIC_KEY_LENGTH, byte]
var rawRecvPubKeyLen = ece_base64url_decode(p256dh.cstring, p256dh.len.csize_t, ECE_BASE64URL_REJECT_PADDING,
                                            addr rawRecvPubKey[0], ECE_WEBPUSH_PUBLIC_KEY_LENGTH)
assert rawRecvPubKeyLen > 0

var authSecret: array[ECE_WEBPUSH_AUTH_SECRET_LENGTH, byte]
var authSecretLen = ece_base64url_decode(auth.cstring, auth.len.csize_t, ECE_BASE64URL_REJECT_PADDING,
                                        addr authSecret[0], ECE_WEBPUSH_AUTH_SECRET_LENGTH)
assert authSecretLen > 0

var padLen: csize_t = 0
var payloadLen = ece_aes128gcm_payload_max_length(ECE_WEBPUSH_DEFAULT_RS,
                                                  padLen, plaintext.len.csize_t)
assert payloadLen > 0

var payload = newSeq[byte](payloadLen)
var err = ece_webpush_aes128gcm_encrypt(addr rawRecvPubKey[0], rawRecvPubKeyLen,
                                        addr authSecret[0], authSecretLen,
                                        ECE_WEBPUSH_DEFAULT_RS, padLen,
                                        cast[ptr byte](plaintext.cstring), plaintext.len.csize_t,
                                        addr payload[0], addr payloadLen);
assert err == ECE_OK
payload.setLen(payloadLen)
echo payload

const filename = "aes128gcm.bin"
writeFile(filename, payload)
echo "curl -v -X POST -H \"Content-Encoding: aes128gcm\" --data-binary ", filename, " ", endpoint
