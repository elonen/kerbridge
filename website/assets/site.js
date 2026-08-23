/* Four small behaviours, no framework, no build step.
 *
 * The agent opens this page with ?os=win|mac because it knows which platform it
 * is running on and the reader should not have to answer a question their own
 * computer already answered. Everything else here is for people who arrive by
 * link or search: guess the platform, honour the system theme, let both be
 * overridden, and remember the override.
 */
(function () {
  'use strict';

  var root = document.documentElement;
  var params = new URLSearchParams(location.search);
  var store = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  };

  /* ── platform ──────────────────────────────────────────────────────────── */

  function guessOs() {
    var p = (navigator.userAgentData && navigator.userAgentData.platform) ||
            navigator.platform || navigator.userAgent || '';
    return /mac|iphone|ipad|ipod/i.test(p) ? 'mac' : 'win';
  }

  // The agent's answer beats a remembered choice, which beats a guess: arriving
  // from the Mac agent should show the Mac page even if you last read the
  // Windows one on this browser.
  var os = params.get('os');
  if (os !== 'win' && os !== 'mac') os = store.get('os') || guessOs();

  function setOs(next) {
    os = next;
    store.set('os', next);
    root.classList.toggle('os-win', next === 'win');
    root.classList.toggle('os-mac', next === 'mac');
    document.querySelectorAll('[data-osbtn]').forEach(function (b) {
      b.setAttribute('aria-pressed', b.dataset.osbtn === next ? 'true' : 'false');
    });
    // Keep the address bar shareable: a link copied after switching shows the
    // reader what the sender was looking at.
    var url = new URL(location.href);
    url.searchParams.set('os', next);
    history.replaceState(null, '', url);
  }

  /* ── theme ─────────────────────────────────────────────────────────────── */

  // Nothing is stamped until someone chooses: with no data-theme the CSS follows
  // prefers-color-scheme, which is the right default and needs no script.
  function setTheme(next) {
    if (next) { root.setAttribute('data-theme', next); store.set('theme', next); }
    else { root.removeAttribute('data-theme'); }
    var dark = next
      ? next === 'dark'
      : matchMedia('(prefers-color-scheme: dark)').matches;
    document.querySelectorAll('[data-themebtn]').forEach(function (b) {
      b.setAttribute('aria-pressed', dark ? 'true' : 'false');
    });
  }

  function toggleTheme() {
    var dark = root.getAttribute('data-theme')
      ? root.getAttribute('data-theme') === 'dark'
      : matchMedia('(prefers-color-scheme: dark)').matches;
    setTheme(dark ? 'light' : 'dark');
  }

  /* ── search ────────────────────────────────────────────────────────────── */

  // Filters whole blocks, and rows within a block that has a table, so a search
  // for a button name lands on the row that names it rather than the section.
  function filter(raw, strings) {
    var q = (raw || '').trim().toLowerCase();
    var hits = 0;

    document.querySelectorAll('[data-sec]').forEach(function (sec) {
      var secHit = false;
      sec.querySelectorAll('[data-block]').forEach(function (block) {
        var rows = Array.prototype.slice.call(block.querySelectorAll('tbody tr'));
        var hit = !q || block.textContent.toLowerCase().indexOf(q) !== -1;
        if (q && rows.length) {
          var rowHit = false;
          rows.forEach(function (r) {
            var m = r.textContent.toLowerCase().indexOf(q) !== -1;
            r.hidden = !m;
            if (m) rowHit = true;
          });
          if (rowHit) hit = true;
          else if (hit) rows.forEach(function (r) { r.hidden = false; });
        } else {
          rows.forEach(function (r) { r.hidden = false; });
        }
        block.hidden = !hit;
        if (hit) { secHit = true; hits += 1; }
      });
      sec.hidden = !secHit;
      var nav = document.querySelector('[data-navfor="' + sec.dataset.sec + '"]');
      if (nav) nav.hidden = !secHit;
    });

    var empty = document.querySelector('[data-empty]');
    if (empty) empty.style.display = q && hits === 0 ? '' : 'none';
    var count = document.querySelector('[data-count]');
    if (count) {
      count.textContent = q
        ? strings.matches.replace('{n}', hits)
        : strings.onThisPage;
    }
  }

  /* ── wiring ────────────────────────────────────────────────────────────── */

  document.addEventListener('DOMContentLoaded', function () {
    var strings = JSON.parse(document.getElementById('ui-strings').textContent);

    setOs(os);
    setTheme(store.get('theme'));

    document.querySelectorAll('[data-osbtn]').forEach(function (b) {
      b.addEventListener('click', function () { setOs(b.dataset.osbtn); });
    });
    document.querySelectorAll('[data-themebtn]').forEach(function (b) {
      b.addEventListener('click', toggleTheme);
    });

    var search = document.querySelector('[data-search]');
    if (search) {
      search.addEventListener('input', function () { filter(search.value, strings); });
    }

    var picker = document.querySelector('[data-langpick]');
    if (picker) {
      picker.addEventListener('change', function () {
        // Sibling directory, parameters carried over.
        location.href = '../' + picker.value + '/' + location.search + location.hash;
      });
    }

    // Marks the contents entry for whatever section is under the header.
    var sections = document.querySelectorAll('[data-sec]');
    if (sections.length && 'IntersectionObserver' in window) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          if (!en.isIntersecting) return;
          document.querySelectorAll('[data-navfor]').forEach(function (a) {
            a.setAttribute('aria-current', a.dataset.navfor === en.target.dataset.sec ? 'true' : 'false');
          });
        });
      }, { rootMargin: '-84px 0px -70% 0px' });
      sections.forEach(function (s) { io.observe(s); });
    }
  });
})();
