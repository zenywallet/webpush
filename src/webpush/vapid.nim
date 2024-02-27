# Copyright (c) 2024 zenywallet

import std/base64
import std/json
import std/strutils
import nimcrypto
import bytes

var jwsHeaderJson = %*{"typ":"JWT","alg":"ES256"}
var jwsPayloadJson = %*{"aud":"https://push.services.mozilla.com","sub":"mailto:admin@example.com","exp":"1463001340"}
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
