# Copyright (c) 2023 zenywallet

import std/marshal
import std/strutils
import std/strformat
import caprese
import capresepkg/exec

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

const WebPushJsTmpl = staticScript:
  import std/jsffi
  import std/macros
  import std/asyncjs
  import karax/[karax, karaxdsl, vdom]
  import jslib

  var pubHex = "<<ServerPubHex>>".cstring
  var appInst: KaraxInstance
  var notificationState = "".cstring
  var prevNotificationState = "".cstring

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
      console.log(JSON.stringify(subscription))
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
  import jsffi

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

server(ssl = true, ip = "0.0.0.0", port = 58009):
  routes:
    echo reqUrl()
    get "/": return IndexHtml.addHeader.send
    get "/sw.js": return ServiceWorkerJs.addHeader("js").send
    get "/webpush.js": return WebPushJs.addHeader("js").send
    get "/site.webmanifest": return SiteManifest.addHeader("json").send
    return "Not found".addHeader(Status404).send

serverStart()
