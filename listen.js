/* Goose Sauna live listen - shared by the tablet (sender) and listen/ (listener).
   Signals go through ntfy.sh, AES-GCM sealed with the #key, so only key holders can talk.
   Audio itself is peer-to-peer WebRTC; nothing is recorded or stored. */
(function () {
  "use strict";
  var RELAY = "https://ntfy.sh/";
  var ICE = [{ urls: ["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"] }];
  var key = (location.hash.match(/key=([A-Za-z0-9_-]{32,})/) || [])[1];
  var enc = new TextEncoder(), dec = new TextDecoder();

  function b64(u8) { var s = ""; for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  function unb64(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); var b = atob(s), u = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  function sha(s) { return crypto.subtle.digest("SHA-256", enc.encode(s)).then(function (h) { return new Uint8Array(h); }); }
  function pipe(u8, T) { return new Response(new Blob([u8]).stream().pipeThrough(new T("deflate-raw"))).arrayBuffer().then(function (b) { return new Uint8Array(b); }); }

  function setup() {
    return Promise.all([sha("topic:" + key), sha("aes:" + key)]).then(function (h) {
      var topic = "gs" + Array.from(h[0].slice(0, 12), function (x) { return x.toString(16).padStart(2, "0"); }).join("");
      return crypto.subtle.importKey("raw", h[1], "AES-GCM", false, ["encrypt", "decrypt"]).then(function (aes) {
        function send(obj) {
          obj.ts = Date.now();
          var iv = crypto.getRandomValues(new Uint8Array(12));
          return pipe(enc.encode(JSON.stringify(obj)), CompressionStream)
            .then(function (z) { return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aes, z); })
            .then(function (ct) { var u = new Uint8Array(12 + ct.byteLength); u.set(iv); u.set(new Uint8Array(ct), 12); return fetch(RELAY + topic, { method: "POST", body: b64(u) }); });
        }
        function listen(onMsg) {
          var es = new EventSource(RELAY + topic + "/sse");
          es.onmessage = function (e) {
            var m; try { m = JSON.parse(e.data); } catch (x) { return; }
            if (m.event !== "message" || !m.message) return;
            var u; try { u = unb64(m.message); } catch (x) { return; }
            crypto.subtle.decrypt({ name: "AES-GCM", iv: u.slice(0, 12) }, aes, u.slice(12))
              .then(function (z) { return pipe(new Uint8Array(z), DecompressionStream); })
              .then(function (j) { var o = JSON.parse(dec.decode(j)); if (Math.abs(Date.now() - o.ts) < 60000) onMsg(o); })
              .catch(function () {}); // not ours, tampered or stale: ignore
          };
          return es;
        }
        return { send: send, listen: listen };
      });
    });
  }

  function gathered(pc) {
    return new Promise(function (ok) {
      if (pc.iceGatheringState === "complete") return ok();
      var t = setTimeout(ok, 2000); // ponytail: vanilla ICE, send what we have after 2 s; trickle ICE if this ever feels slow
      pc.addEventListener("icegatheringstatechange", function () { if (pc.iceGatheringState === "complete") { clearTimeout(t); ok(); } });
    });
  }

  window.GSL = { key: key, setup: setup, gathered: gathered, ICE: ICE, b64: b64 };
  if (window.GSL_LISTENER || !key) return;

  // ---- tablet side: silent. Mic opens only for a sealed, fresh offer; closes when the peer leaves.
  var pc = null, mic = null, cur = null;
  function hang() {
    if (mic) mic.getTracks().forEach(function (t) { t.stop(); });
    if (pc) pc.close();
    pc = mic = cur = null;
  }
  setup().then(function (ch) {
    ch.listen(function (m) {
      if (m.t === "bye" && m.id === cur) return hang();
      if (m.t !== "offer" || m.id === cur) return;
      hang(); cur = m.id;
      var id = m.id, p = new RTCPeerConnection({ iceServers: ICE });
      pc = p;
      p.onconnectionstatechange = function () { if (pc === p && /failed|closed|disconnected/.test(p.connectionState)) hang(); };
      navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: true } })
        .then(function (s) { if (pc !== p) { s.getTracks().forEach(function (t) { t.stop(); }); throw 0; } mic = s; s.getTracks().forEach(function (t) { p.addTrack(t, s); }); })
        .then(function () { return p.setRemoteDescription({ type: "offer", sdp: m.sdp }); })
        .then(function () { return p.createAnswer(); })
        .then(function (a) { return p.setLocalDescription(a); })
        .then(function () { return gathered(p); })
        .then(function () { if (pc === p) return ch.send({ t: "answer", id: id, sdp: p.localDescription.sdp }); })
        .catch(function (e) { if (pc === p) { if (e) ch.send({ t: "err", id: id, why: String(e && e.name || e) }); hang(); } });
    });
  }).catch(function () {});
})();
