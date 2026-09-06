// Freehold site — shared chrome, fully self-contained. Injects a consistent top nav (with its OWN
// scoped styles, so it can drop onto the functional demo pages without touching their CSS) plus a
// scroll-reveal observer. Include with:
//   <script type="module" src="./site-nav.js" data-page="demos"></script>
// On the landing/docs pages (which hand-roll a .nav via site.css) it no-ops the nav and just wires
// the reveal observer. `data-page` marks the active link.

const GH = 'https://github.com/JSBtechnologies/freehold';

const LINKS = [
  { id: 'home',  href: './index.html',   label: 'Home' },
  { id: 'demos', href: './passkey.html', label: 'Passkey' },
  { id: 'custody', href: './custody.html', label: 'Custody' },
  { id: 'docs',  href: './docs.html',    label: 'Docs' },
];

const MARK = `<svg viewBox="0 0 32 32" width="24" height="24" fill="none" aria-hidden="true">
  <rect x="2.5" y="2.5" width="27" height="27" rx="7" stroke="url(#fhg)" stroke-width="2"/>
  <path d="M11 22V10h9M11 16h6" stroke="url(#fhg)" stroke-width="2.2" stroke-linecap="round"/>
  <defs><linearGradient id="fhg" x1="0" y1="0" x2="32" y2="32">
    <stop stop-color="#f2c877"/><stop offset="1" stop-color="#7c9cff"/></linearGradient></defs></svg>`;

const NAV_CSS = `
.fh-nav{position:sticky;top:0;z-index:9999;backdrop-filter:saturate(140%) blur(12px);
  background:rgba(10,13,22,.82);border-bottom:1px solid #222c44;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;}
.fh-nav .fh-in{max-width:1080px;margin:0 auto;padding:11px 22px;display:flex;align-items:center;gap:20px;}
.fh-nav .fh-brand{display:flex;align-items:center;gap:9px;font-weight:700;font-size:15.5px;color:#eef2fb;text-decoration:none;letter-spacing:-.01em;}
.fh-nav .fh-ln{display:flex;gap:18px;margin-left:auto;align-items:center;}
.fh-nav .fh-ln a{color:#8b97b4;font-size:14px;font-weight:500;text-decoration:none;}
.fh-nav .fh-ln a:hover{color:#eef2fb;}
.fh-nav .fh-ln a.on{color:#eef2fb;}
.fh-nav .fh-ln a.fh-cta{color:#0a0d16;background:linear-gradient(180deg,#f2c877,#e8b559);padding:6px 13px;border-radius:9px;font-weight:650;}
.fh-nav .fh-ln a.fh-cta:hover{filter:brightness(1.06);color:#0a0d16;}
@media(max-width:620px){.fh-nav .fh-ln a.fh-hide{display:none;}}
`;

function injectNav() {
  if (document.querySelector('.nav') || document.querySelector('.fh-nav')) return; // page has its own
  const active = document.querySelector('script[data-page]')?.dataset.page || '';
  const style = document.createElement('style');
  style.textContent = NAV_CSS;
  document.head.appendChild(style);
  const links = LINKS.map(
    (l) => `<a href="${l.href}" class="${l.id === active ? 'on' : ''}${l.id === 'custody' ? ' fh-hide' : ''}">${l.label}</a>`
  ).join('');
  const nav = document.createElement('nav');
  nav.className = 'fh-nav';
  nav.innerHTML = `<div class="fh-in">
    <a class="fh-brand" href="./index.html">${MARK}<span>Freehold</span></a>
    <div class="fh-ln">${links}
      <a class="fh-hide" href="${GH}" target="_blank" rel="noopener">GitHub ↗</a>
      <a class="fh-cta" href="./index.html">← Home</a>
    </div>
  </div>`;
  document.body.prepend(nav);
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
