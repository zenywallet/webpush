# Copyright (c) 2023 zenywallet

import std/marshal
import std/strutils
import std/strformat
import std/json
import std/base64
import std/uri
import libcurl
import caprese
import capresepkg/exec
import ece
import vapid

const keyResult = staticExecCode:
  import std/marshal
  import webpush

  var pair = loadKey()
  if not pair.isValid():
    pair = genKey()
    pair.save()
  echo $$(prv: pair.prv, pub: pair.pub)
  pair.clear()

const (serverPrv, serverPub) = to[tuple[prv, pub: seq[byte]]](keyResult)
const ServerPubHex = serverPub.toHex

macro staticEncode(data: static openArray[byte]): untyped =
  var enc = base64.encode(data, true)
  enc.removeSuffix('=')
  newLit(enc)

const ServerPubEnc = staticEncode(serverPub)
echo "ServerPubEnc=", ServerPubEnc

var vapidPrvKey: VapidPrvKey = getVapidPrvKey(serverPrv)

const VapidSubject = "https://localhost" # "mailto:<mail address>"

const WebPushJsTmpl = staticScript:
  import std/jsffi
  import std/macros
  import std/asyncjs
  import std/strformat
  import karax/[karax, karaxdsl, vdom]
  import jslib
  import jsstream

  var pubHex = "<<ServerPubHex>>".cstring
  var appInst: KaraxInstance
  var notificationState = "".cstring
  var prevNotificationState = "".cstring
  var stream: Stream

  proc jq(selector: cstring): JsObject {.importcpp: "$$(#)".}
  converter futureConv(jsObj: JsObject): Future[JsObject] = cast[Future[JsObject]](jsObj)

  type Notify = enum
    Success
    Error
    Warning
    Info

  proc show(notify: Notify, msg: cstring, tag: string = "", infinite: bool = false) =
    let notifyVal = case notify
      of Success: "success".cstring
      of Error: "error".cstring
      of Warning: "warn".cstring
      of Info: "info".cstring
    jq("body").toast(JsObject{
      position: "bottom right".cstring,
      title: ("WebPush - " & $notify).cstring,
      message: msg,
      class: notifyVal,
      className: JsObject{
        toast: (if tag.len > 0: ("ui message " & tag).cstring else: "ui message".cstring)
      },
      displayTime: (if infinite: 0 else: 5000)
    })

  proc clearNotify(tag: string = "") =
    var dottag = (if tag.len > 0: "." & tag else: "")
    jq((".ui.message" & dottag).cstring).toast("close")

  template fmtj(pattern: static string): untyped = fmt(pattern, '<', '>')

  proc cmdSend(cmd: string) = stream.send(strToUint8Array(cmd.cstring))

  proc hookChangeEvent() {.async, discardable.} =
    var permissionStatus = await navigator.permissions.query(JsObject{name: "notifications".cstring})
    permissionStatus.onchange = proc(evt: JsObject) =
      prevNotificationState = notificationState
      notificationState = permissionStatus.state.to(cstring)
      appInst.redraw()
      if prevNotificationState == "granted" and notificationState != "granted":
        Notify.Info.show("webpush disabled")
      elif prevNotificationState != "granted" and notificationState == "granted":
        Notify.Info.show("webpush enabled")
    notificationState = permissionStatus.state.to(cstring)
    appInst.redraw()

  type
    DOMException {.importc: "DOMException".} = object

  proc allowWebPush() {.async, discardable.} =
    if "Notification".toJs.in(window).to(bool):
      let permission = window.Notification.permission
      if permission == "denied".toJs:
        Notify.Error.show("webpush denied")
        return
      elif permission == "granted".toJs:
        var swr = await navigator.serviceWorker.ready
        var subscription = await swr.pushManager.getSubscription()
        var pushSubscription = $(JSON.stringify(subscription).to(cstring))
        echo pushSubscription
        cmdSend fmtj"""{"cmd":"pushSubscription","data":<pushSubscription>}"""

        Notify.Info.show("webpush permitted")
        return
    else:
      Notify.Error.show("web push notification is not supported")
      return

    try:
      var subscription = await window.sw.pushManager.subscribe(JsObject{
        userVisibleOnly: true,
        applicationServerKey: hexToUint8Array(pubHex)
      })
      var pushSubscription = $(JSON.stringify(subscription).to(cstring))
      echo pushSubscription
      cmdSend fmtj"""{"cmd":"pushSubscription","data":<pushSubscription>}"""

    except DOMException as e:
      console.log(e)
      let permissionStr = window.Notification.permission.to(cstring)
      Notify.Error.show("webpush " & permissionStr)
      prevNotificationState = notificationState
      notificationState = permissionStr

  proc appMain(): VNode =
    buildHtml(buildHtml(tdiv(class="ui inverted main text container"))):
      h1(class="ui inverted dividing header"): text "WebPush Server Test"
      form(class="ui inverted large form"):
        tdiv(class="field"):
          label: text "Notification State"
          tdiv(class="ul label"):
            text notificationState
        tdiv(class="ui inverted ok button"):
          proc onclick(ev: Event, n: Vnode) =
            discard allowWebPush()
          text "Set WebPush Notification"

  template runAsync(body: untyped) =
    discard (proc(): Future[JsObject] {.async.} =
      body
    )()

  template domReady(body: untyped) =
    if document.readyState == "loading".toJs:
      document.addEventListener("DOMContentLoaded", proc(evt: JsObject) = body)
    else:
      body

  stream.connect(url = "wss://localhost:58009/ws", protocol = "webpush"):
    onOpen:
      echo "onOpen"

  runAsync:
    if "serviceWorker".toJs.in(navigator).to(bool):
      window.sw = await navigator.serviceWorker.register("sw.js")

    domReady:
      appInst = setRenderer(appMain, "main")
      appInst.surpressRedraws = false
      appInst.redraw()
      hookChangeEvent()

const WebPushOrgJs = WebPushJsTmpl.replace("<<ServerPubHex>>", ServerPubHex)
const WebPushMinJs = scriptMinifier(WebPushOrgJs, """
var fomantic = {
  tab: 0,
  checkbox: 0,
  rating: {
    icon: 0,
    initialRating: 0,
    maxRating: 0,
    fireOnInit: 0,
    clearable: 0,
    interactive: 0,
    onRate: function() {},
    onChange: function() {}
  },
  toast: {
    position: 0,
    title: 0,
    message: 0,
    class: 0,
    className: {
      toast: 0
    },
    displayTime: 0
  },
  modal: {
    onShow: function() {},
    onVisible: function() {},
    onHide: function() {},
    onHidden: function() {},
    onApprove: function() {},
    onDeny: function() {}
  }
};
""")

const ServiceWorkerJsTmpl = staticScript:
  import std/jsffi

  type
    SelfObj = JsObject
    ConsoleObj = JsObject
    ClientsObj = JsObject

  var self {.importc, nodecl.}: SelfObj
  var console {.importc, nodecl.}: ConsoleObj
  var clients {.importc, nodecl.}: ClientsObj

  self.addEventListener "push", proc(evt: JsObject) =
    console.log("addEventListener push")
    var title = "push".cstring
    var options = JsObject{
      body: evt.data.text(),
      tag: title,
      icon: "icon-512x512.png".cstring,
      badge: "icon-512x512.png".cstring
    }
    evt.waitUntil(self.registration.showNotification(title, options))

  self.addEventListener "notificationclick", proc(evt: JsObject) =
    evt.notification.close()
    evt.waitUntil(clients.openWindow("<<WebPushNotificationUrl>>"))

  self.addEventListener "install", proc(evt: JsObject) =
    console.log("service worker install")

const WebPushNotificationUrl = "https://localhost:58009/"
const ServiceWorkerOrgJs = ServiceWorkerJsTmpl.replace("<<WebPushNotificationUrl>>", WebPushNotificationUrl)
const ServiceWorkerMinJs = scriptMinifier(ServiceWorkerOrgJs, "")

when defined(release):
  const WebPushJs = WebPushMinJs
  const ServiceWorkerJs = ServiceWorkerMinJs
else:
  const WebPushJs = WebPushOrgJs
  const ServiceWorkerJs = ServiceWorkerOrgJs

const Css = keepIndent """
body {
  background-color: #414b52;
  color: #cfdae3;
}
.main.container {
  padding-top: 2em;
  padding-bottom: 6em;
}
"""

const SiteManifest = """
{
  "name": "WebPush",
  "short_name": "WebPush",
  "icons": [
    {
      "src": "/icon-192x192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "/icon-512x512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ],
  "theme_color": "#ffffff",
  "background_color": "#ffffff",
  "display": "standalone",
  "orientation": "portrait",
  "start_url": "."
}
"""

const IndexHtml = staticHtmlDocument:
  buildHtml(html):
    head:
      meta(charset="utf-8")
      title: text "WebPush Server"
      link(rel="icon", href="data:,")
      link(rel="manifest", href="/site.webmanifest")
      script(src="https://cdn.jsdelivr.net/npm/jquery@3.6.3/dist/jquery.min.js")
      link(rel="stylesheet", type="text/css", href="https://cdn.jsdelivr.net/npm/fomantic-ui@2.9.2/dist/semantic.min.css")
      script(src="https://cdn.jsdelivr.net/npm/fomantic-ui@2.9.2/dist/semantic.min.js")
      style: verbatim Css
      script(src="/webpush.js")
    body:
      tdiv(id="main")

const ICON_512_FILENAME = "icon-512x512.png"
const ICON_128_FILENAME = "icon-128x128.png"

when not fileExists(currentSourcePath.parentDir() / ICON_512_FILENAME):
  staticExecCode:
    import pixie
    const ICON_512_FILENAME = "icon-512x512.png"
    let image = newImage(512, 512)
    let ctx = newContext(image)
    ctx.fillStyle = rgba(0, 0, 225, 255)
    let pos = vec2(32, 32)
    let wh = vec2(448, 448)
    ctx.fillRect(rect(pos, wh))
    echo image.encodeImage(PngFormat)
    image.writeFile(ICON_512_FILENAME)

when not fileExists(currentSourcePath.parentDir() / ICON_128_FILENAME):
  staticExecCode:
    import pixie
    const ICON_128_FILENAME = "icon-128x128.png"
    let image = newImage(128, 128)
    let ctx = newContext(image)
    ctx.fillStyle = rgba(0, 0, 225, 255)
    let pos = vec2(8, 8)
    let wh = vec2(112, 112)
    ctx.fillRect(rect(pos, wh))
    echo image.encodeImage(PngFormat)
    image.writeFile(ICON_128_FILENAME)

const ICON_512 = staticRead(ICON_512_FILENAME)
const ICON_128 = staticRead(ICON_128_FILENAME)

type
  PendingData = object
    msg: string

var reqs: Pendings[PendingData]
reqs.newPending(limit = 100)

worker(num = 2):
  reqs.recvLoop(req):
    var cmdData = parseJson(req.data.msg)
    var pushSubscription = cmdData["data"]
    echo "json=", $pushSubscription
    var endpoint = pushSubscription["endpoint"].getStr()
    echo "endpoint=", endpoint
    var auth = pushSubscription["keys"]["auth"].getStr()
    var p256dh = pushSubscription["keys"]["p256dh"].getStr()
    echo "auth=", auth
    echo "p256dh=", p256dh
    var plaintext = "I'm just like my country, I'm young, scrappy, and " &
                    "hungry, and I'm not throwing away my shot."


    var rawRecvPubKey: array[ECE_WEBPUSH_PUBLIC_KEY_LENGTH, byte]
    var rawRecvPubKeyLen = ece_base64url_decode((addr p256dh[0]).cstring, p256dh.len.csize_t, ECE_BASE64URL_REJECT_PADDING,
                                                addr rawRecvPubKey[0], ECE_WEBPUSH_PUBLIC_KEY_LENGTH)
    doAssert rawRecvPubKeyLen > 0

    var authSecret: array[ECE_WEBPUSH_AUTH_SECRET_LENGTH, byte]
    var authSecretLen = ece_base64url_decode((addr auth[0]).cstring, auth.len.csize_t, ECE_BASE64URL_REJECT_PADDING,
                                            addr authSecret[0], ECE_WEBPUSH_AUTH_SECRET_LENGTH)
    doAssert authSecretLen > 0

    var padLen: csize_t = 0
    var payloadLen = ece_aes128gcm_payload_max_length(ECE_WEBPUSH_DEFAULT_RS,
                                                      padLen, plaintext.len.csize_t)
    doAssert payloadLen > 0

    var payload = newSeq[byte](payloadLen)
    var err = ece_webpush_aes128gcm_encrypt(addr rawRecvPubKey[0], rawRecvPubKeyLen,
                                            addr authSecret[0], authSecretLen,
                                            ECE_WEBPUSH_DEFAULT_RS, padLen,
                                            cast[ptr byte](plaintext.cstring), plaintext.len.csize_t,
                                            addr payload[0], addr payloadLen)
    doAssert err == ECE_OK
    payload.setLen(payloadLen)
    echo "payload=", payload

    var url = parseUri(endpoint)
    var audience = url.scheme & "://" & url.hostname
    echo "audience=", audience

    var headers: PSlist
    headers = slist_append(headers, "Content-Type: application/octet-stream")
    headers = slist_append(headers, "Content-Encoding: aes128gcm")
    headers = slist_append(headers, "TTL: 2419200")
    headers = slist_append(headers, "Authorization: " &
                getVapidAuthorization(audience, VapidSubject, ServerPubEnc, vapidPrvKey))

    var outbuf: ref string = new string
    let curl: Pcurl = easy_init()
    discard curl.easy_setopt(OPT_VERBOSE, 1)
    discard curl.easy_setopt(OPT_URL, endpoint.cstring)
    discard curl.easy_setopt(OPT_POST, 1)
    discard curl.easy_setopt(OPT_POSTFIELDS, addr payload[0])
    discard curl.easy_setopt(OPT_POSTFIELDSIZE, payload.len)
    discard curl.easy_setopt(OPT_WRITEDATA, outbuf)

    proc writeCallback(buffer: cstring, size: int, nitems: int, outstream: pointer): int =
      var outbuf = cast[ref string](outstream)
      outbuf[] &= buffer
      echo "outbuf len=", outbuf[].len
      result = size * nitems

    discard curl.easy_setopt(OPT_WRITEFUNCTION, writeCallback)
    discard curl.easy_setopt(OPT_HTTPHEADER, headers)
    let ret = curl.easy_perform()
    curl.easy_cleanup()
    echo ret, outbuf[]

server(ssl = true, ip = "0.0.0.0", port = 58009):
  routes:
    echo reqUrl()
    get "/": return IndexHtml.content.response
    get "/sw.js": return ServiceWorkerJs.content("js").response
    get "/webpush.js": return WebPushJs.content("js").response
    get "/site.webmanifest": return SiteManifest.content("json").response
    get "/icon-512x512.png": return ICON_512.content("png").response
    get "/icon-128x128.png": return ICON_128.content("png").response

    stream "/ws":
      onOpen:
        echo "onOpen"

      onMessage:
        echo "data=", data.toString(size)
        return reqs.pending(PendingData(msg: data.toString(size)))

      onClose:
        echo "onClose"

    return "Not found".addHeader(Status404).send

serverStart()
