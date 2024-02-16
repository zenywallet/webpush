# Copyright (c) 2024 zenywallet

import ece
import bytes

var rawSubPrivKey: array[ECE_WEBPUSH_PRIVATE_KEY_LENGTH, byte]
var authSecret: array[ECE_WEBPUSH_AUTH_SECRET_LENGTH, byte]

var payload: array[100, byte]
var payloadLen = 0.csize_t

var plaintextLen = ece_aes128gcm_plaintext_max_length(addr payload[0], payloadLen.csize_t)
assert plaintextLen > 0

var plaintext = newSeq[byte](plaintextLen)
var err = ece_webpush_aes128gcm_decrypt(addr rawSubPrivKey[0], ECE_WEBPUSH_PRIVATE_KEY_LENGTH,
                                        addr authSecret[0], ECE_WEBPUSH_AUTH_SECRET_LENGTH,
                                        addr payload[0], payloadLen.csize_t, addr plaintext[0], addr plaintextLen)
assert err == ECE_OK
