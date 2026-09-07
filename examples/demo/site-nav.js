// Freehold site — the ONE shared header, injected on every page (landing, docs, live demos) so the
// chrome is identical everywhere. Accessible + responsive: a horizontal nav on desktop and an
// accessible disclosure menu (hamburger) on mobile, a skip-to-content link, aria-current on the active
// link, keyboard support (Enter/Space/Esc), and visible focus. Self-contained scoped styles so it
// drops onto the functional demo pages without touching their CSS. Include with:
//   <script type="module" src="./site-nav.js" data-page="passkey"></script>

const GH = 'https://github.com/JSBtechnologies/freehold';

const LINKS = [
  { id: 'docs',    href: './docs.html',    label: 'Docs' },
  { id: 'passkey', href: './passkey.html', label: 'Passkey demo' },
  { id: 'custody', href: './custody.html', label: 'Custody demo' },
  { id: 'github',  href: GH,               label: 'GitHub ↗', external: true },
];

const MARK = `<svg viewBox="0 0 32 32" width="26" height="26" fill="none" aria-hidden="true" focusable="false">
  <rect x="2.5" y="2.5" width="27" height="27" rx="7" stroke="url(#fhg)" stroke-width="2"/>
  <path d="M11 22V10h9M11 16h6" stroke="url(#fhg)" stroke-width="2.2" stroke-linecap="round"/>
  <defs><linearGradient id="fhg" x1="0" y1="0" x2="32" y2="32">
    <stop stop-color="#f2c877"/><stop offset="1" stop-color="#7c9cff"/></linearGradient></defs></svg>`;

const NAV_CSS = `
.fh-skip{position:fixed;top:8px;left:8px;z-index:10001;transform:translateY(-160%);
  background:#0d111d;color:#eef2fb;border:1px solid #3b486e;border-radius:8px;padding:10px 14px;
  font:600 14px ui-sans-serif,system-ui,sans-serif;text-decoration:none;transition:transform .15s;}
.fh-skip:focus{transform:none;outline:2px solid #7c9cff;outline-offset:2px;}
.fh-nav{position:sticky;top:0;z-index:9999;backdrop-filter:saturate(140%) blur(12px);
  background:rgba(10,13,22,.82);border-bottom:1px solid #222c44;
  font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Inter,sans-serif;}
.fh-nav *{box-sizing:border-box;}
.fh-nav .fh-in{max-width:1080px;margin:0 auto;padding:10px 20px;display:flex;align-items:center;gap:16px;}
.fh-nav .fh-brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;color:#eef2fb;
  text-decoration:none;letter-spacing:-.01em;min-height:44px;}
.fh-nav .fh-ln{display:flex;gap:6px;margin-left:auto;align-items:center;}
.fh-nav .fh-ln a{color:#c3cce0;font-size:14.5px;font-weight:500;text-decoration:none;transition:color .15s,background .15s;
  padding:8px 11px;border-radius:8px;display:inline-flex;align-items:center;min-height:40px;}
.fh-nav .fh-ln a:hover{color:#fff;background:rgba(124,156,255,.08);}
.fh-nav .fh-ln a[aria-current="page"]{color:#fff;background:rgba(124,156,255,.12);}
.fh-nav .fh-cta{margin-left:6px;color:#0a0d16 !important;background:linear-gradient(180deg,#f2c877,#e8b559);
  font-weight:650;padding:9px 15px !important;border-radius:9px;}
.fh-nav .fh-cta:hover{filter:brightness(1.06);background:linear-gradient(180deg,#f2c877,#e8b559) !important;}
.fh-nav .fh-toggle{display:none;margin-left:auto;background:transparent;border:1px solid #2c3856;border-radius:9px;
  color:#eef2fb;width:44px;height:44px;align-items:center;justify-content:center;cursor:pointer;}
.fh-nav .fh-toggle svg{width:22px;height:22px;}
/* visible keyboard focus everywhere in the header */
.fh-nav a:focus-visible,.fh-nav button:focus-visible,.fh-skip:focus-visible{outline:2px solid #7c9cff;outline-offset:2px;}
@media(max-width:720px){
  .fh-nav .fh-toggle{display:inline-flex;}
  .fh-nav .fh-ln{position:absolute;left:0;right:0;top:100%;flex-direction:column;align-items:stretch;gap:2px;
    margin:0;padding:8px;background:#0d111d;border-bottom:1px solid #222c44;box-shadow:0 18px 40px -20px #000;
    display:none;}
  .fh-nav.fh-open .fh-ln{display:flex;}
  .fh-nav .fh-ln a{min-height:46px;padding:12px 14px;font-size:16px;}
  .fh-nav .fh-cta{margin:6px 0 2px;justify-content:center;}
  .fh-nav .fh-in{position:relative;}
}
@media (prefers-reduced-motion: reduce){.fh-skip{transition:none;}}
/* Global keyboard-focus visibility on every page this header ships to (incl. the demo pages,
   which don't load site.css). Only paints on keyboard focus, so it doesn't disturb mouse use. */
a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible,[tabindex]:focus-visible{outline:2px solid #7c9cff;outline-offset:2px;}
`;

function findMain() {
  return document.querySelector('main, [role="main"], .docs-main, .hero, section, article');
}

function injectNav() {
  if (document.querySelector('.fh-nav')) return;
  document.querySelector('nav.nav')?.remove();

  const active = document.querySelector('script[data-page]')?.dataset.page || '';
  const style = document.createElement('style');
  style.textContent = NAV_CSS;
  document.head.appendChild(style);

  // Skip-to-content link → the first main region (given an id + programmatic focus target).
  const main = findMain();
  if (main && !main.id) main.id = 'fh-main';
  const skip = document.createElement('a');
  skip.className = 'fh-skip';
  skip.href = '#' + (main ? main.id : 'fh-main');
  skip.textContent = 'Skip to main content';
  if (main) { main.setAttribute('tabindex', '-1'); }
  document.body.prepend(skip);

  const links = LINKS.map((l) => {
    const cur = l.id === active ? ' aria-current="page"' : '';
    const ext = l.external ? ' target="_blank" rel="noopener"' : '';
    return `<a href="${l.href}"${cur}${ext}>${l.label}</a>`;
  }).join('');

  const nav = document.createElement('nav');
  nav.className = 'fh-nav';
  nav.setAttribute('aria-label', 'Primary');
  nav.innerHTML = `<div class="fh-in">
    <a class="fh-brand" href="./index.html" aria-label="Freehold — home">${MARK}<span>Freehold</span></a>
    <button class="fh-toggle" aria-label="Open menu" aria-expanded="false" aria-controls="fh-menu">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
    </button>
    <div class="fh-ln" id="fh-menu">${links}
      <a class="fh-cta" href="./passkey.html">Try the demo</a>
    </div>
  </div>`;
  document.body.prepend(nav);

  // Accessible disclosure behavior for the mobile menu.
  const toggle = nav.querySelector('.fh-toggle');
  const menu = nav.querySelector('#fh-menu');
  const setOpen = (open) => {
    nav.classList.toggle('fh-open', open);
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    if (open) { const first = menu.querySelector('a'); if (first) first.focus(); }
  };
  toggle.addEventListener('click', () => setOpen(toggle.getAttribute('aria-expanded') !== 'true'));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && toggle.getAttribute('aria-expanded') === 'true') { setOpen(false); toggle.focus(); }
  });
  document.addEventListener('click', (e) => {
    if (toggle.getAttribute('aria-expanded') === 'true' && !nav.contains(e.target)) setOpen(false);
  });
  menu.addEventListener('click', (e) => { if (e.target.tagName === 'A') setOpen(false); });
}

function revealObserver() {
  const els = document.querySelectorAll('.reveal');
  if (!els.length) return;
  if (!('IntersectionObserver' in window)) { els.forEach((e) => e.classList.add('in')); return; }
  const io = new IntersectionObserver(
    (entries) => entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }),
    { rootMargin: '0px 0px -8% 0px', threshold: 0.08 }
  );
  els.forEach((e) => io.observe(e));
}

injectNav();
if (document.readyState !== 'loading') revealObserver();
else document.addEventListener('DOMContentLoaded', revealObserver);
