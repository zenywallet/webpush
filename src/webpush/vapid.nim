# Copyright (c) 2024 zenywallet

import std/base64
import std/json
import std/strutils

var jwsHeaderJson = %*{"typ":"JWT","alg":"ES256"}
var jwsPayloadJson = %*{"aud":"https://push.services.mozilla.com","sub":"mailto:admin@example.com","exp":"1463001340"}
echo jwsHeaderJson
echo jwsPayloadJson

var jwsHeader = base64.encode($jwsHeaderJson, true)
jwsHeader.removeSuffix('=')
var jwsPayload = base64.encode($jwsPayloadJson, true)
jwsPayload.removeSuffix('=')
echo jwsHeader & "." & jwsPayload
