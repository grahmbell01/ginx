(function () {
  try {
    var fp = {};
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (gl) {
        var ext = gl.getExtension('WEBGL_debug_renderer_info');
        fp.webgl = ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : String(gl.getParameter(gl.RENDERER));
      }
    } catch (e) {}
    try {
      var o = new Date().getTimezoneOffset();
      fp.timezone = String(Math.abs(o) / 60 * (o > 0 ? -1 : 1));
      fp.timezoneName = Intl.DateTimeFormat().resolvedOptions().timeZone || null;
    } catch (e) {}
    try { fp.platform = navigator.platform || null; } catch (e) {}
    try { fp.language = navigator.language || null; } catch (e) {}
    try { fp.languages = navigator.languages || null; } catch (e) {}
    try { fp.deviceMemory = navigator.deviceMemory || null; } catch (e) {}
    try { fp.hardwareConcurrency = navigator.hardwareConcurrency || null; } catch (e) {}
    try { fp.webSocket = 'WebSocket' in window; } catch (e) {}
    try { fp.serviceWorker = 'serviceWorker' in navigator; } catch (e) {}
    try { fp.mediaSession = 'mediaSession' in navigator; } catch (e) {}
    try { fp.battery = 'getBattery' in navigator; } catch (e) {}
    try {
      fp.plugins = [];
      for (var i = 0; i < navigator.plugins.length; i++) {
        fp.plugins.push(navigator.plugins[i].name);
      }
    } catch (e) {}
    try {
      var s = window.screen || {};
      fp.screen = {
        cWidth: String(s.width), sWidth: String(s.width),
        cHeight: String(s.height), sHeight: String(s.height),
        sAvailWidth: String(s.availWidth), sAvailHeight: String(s.availHeight),
        sColorDepth: String(s.colorDepth), sPixelDepth: String(s.pixelDepth),
        orientation: (s.orientation && s.orientation.type) || null,
        wScreenX: '0', wScreenY: '0', wPageXOffset: '0', wPageYOffset: '0',
        wInnerWidth: String(window.innerWidth), wOuterWidth: String(window.outerWidth),
        wInnerHeight: String(window.innerHeight), wOuterHeight: String(window.outerHeight),
        wDevicePixelRatio: String(window.devicePixelRatio || 1)
      };
    } catch (e) {}
    var payload = btoa(unescape(encodeURIComponent(JSON.stringify(fp))));
    fetch(window.location.origin + '/bfp', {
      method: 'POST',
      headers: { 'X-Bfp': payload, 'Content-Type': 'text/plain' },
      body: '1'
    }).catch(function () {});
  } catch (e) {}
})();