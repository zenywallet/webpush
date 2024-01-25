# Copyright (c) 2023 zenywallet

import ece
import bytes

var rawRecvPrivKey = newSeq[byte](ECE_WEBPUSH_PRIVATE_KEY_LENGTH)
var rawRecvPubKey = newSeq[byte](ECE_WEBPUSH_PUBLIC_KEY_LENGTH)
var authSecret = newSeq[byte](ECE_WEBPUSH_AUTH_SECRET_LENGTH)

var err = ece_webpush_generate_keys(addr rawRecvPrivKey[0], ECE_WEBPUSH_PRIVATE_KEY_LENGTH,
                                    addr rawRecvPubKey[0], ECE_WEBPUSH_PUBLIC_KEY_LENGTH,
                                    addr authSecret[0], ECE_WEBPUSH_AUTH_SECRET_LENGTH)
echo "err=", err

echo "rawRecvPrivKey=", rawRecvPrivKey
echo "rawRecvPubKey=", rawRecvPubKey
echo "authSecret=", authSecret
