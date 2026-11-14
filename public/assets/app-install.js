(function () {
  'use strict';

  // Register service worker (relative so it works from any path)
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(function () {});
  }

  // Already running as installed app -> nothing to offer
  var standalone = window.matchMedia('(display-mode: standalone)').matches
    || window.matchMedia('(display-mode: window-controls-overlay)').matches
    || (navigator.standalone === true);
  if (standalone) return;

  var deferred = null;
  var btn = null;
  var isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent)
    && !/crios|fxios|edgiOS/i.test(navigator.userAgent);

  function dismiss() {
    try { localStorage.setItem('bgi-install-dismissed', '1'); } catch (e) {}
    if (btn) btn.remove();
    btn = null;
  }
  try { if (localStorage.getItem('bgi-install-dismissed') === '1' && !isIOS) return; } catch (e) {}

  function build(text, hint, onclick) {
    var b = document.createElement('button');
    b.type = 'button';
    b.setAttribute('aria-label', text);
    b.innerHTML =
      '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"' +
      ' stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      '<path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M4 21h16"/></svg>' +
      '<span>' + text + '</span>';
    var css = document.createElement('style');
    css.textContent =
      '.bgi-install{position:fixed;right:18px;bottom:18px;z-index:99999;display:flex;' +
      'align-items:center;gap:8px;padding:10px 16px;border-radius:999px;border:1px solid #3ecfae;' +
      'background:#131a2b;color:#3ecfae;font:600 13px system-ui,-apple-system,"Segoe UI",sans-serif;' +
      'cursor:pointer;box-shadow:0 8px 24px rgba(0,0,0,.45);transition:transform .15s,background .15s}' +
      '.bgi-install:hover{background:#1a2338;transform:translateY(-2px)}' +
      '.bgi-install .hint{color:#8fa0c0;font-weight:500}' +
      '.bgi-install .x{margin-left:4px;color:#8fa0c0;background:none;border:none;cursor:pointer;' +
      'font-size:15px;line-height:1;padding:2px}';
    document.head.appendChild(css);
    if (hint) {
      var h = document.createElement('span');
      h.className = 'hint';
      h.textContent = hint;
      b.appendChild(h);
    }
    var x = document.createElement('button');
    x.className = 'x';
    x.type = 'button';
    x.setAttribute('aria-label', 'Close');
    x.textContent = '\u00d7';
    x.addEventListener('click', function (e) { e.stopPropagation(); dismiss(); });
    b.appendChild(x);
    b.addEventListener('click', onclick);
    document.body.appendChild(b);
    return b;
  }

  window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault();
    deferred = e;
    if (!btn) {
      btn = build('Install App', '(runs as a desktop app)', function () {
        if (!deferred) return;
        deferred.prompt();
        deferred.userChoice.then(function (choice) {
          if (choice.outcome === 'accepted') dismiss();
          deferred = null;
        });
      });
    }
  });

  // iOS Safari: no install prompt, show guide link instead
  if (isIOS) {
    btn = build('Install App', '(see guide)', function () {
      location.href = './install.html';
    });
  }

  window.addEventListener('appinstalled', dismiss);
})();
