// Freehold site — the ONE shared header, injected on every page (landing, docs, and the live demos)
// so the chrome is identical everywhere. Self-contained scoped styles, so it drops onto the
// functional demo pages without touching their CSS. Include with:
//   <script type="module" src="./site-nav.js" data-page="demos"></script>
// `data-page` marks the active link. Also wires the scroll-reveal observer used on the landing/docs.

const GH = 'https://github.com/JSBtechnologies/freehold';

const LINKS = [
  { id: 'docs',    href: './docs.html',    label: 'Docs' },
  { id: 'passkey', href: './passkey.html', label: 'Passkey demo' },
  { id: 'custody', href: './custody.html', label: 'Custody demo' },
];

const MARK = `<svg viewBox="0 0 32 32" width="26" height="26" fill="none" aria-hidden="true">
  <rect x="2.5" y="2.5" width="27" height="27" rx="7" stroke="url(#fhg)" stroke-width="2"/>
  <path d="M11 22V10h9M11 16h6" stroke="url(#fhg)" stroke-width="2.2" stroke-linecap="round"/>
  <defs><linearGradient id="fhg" x1="0" y1="0" x2="32" y2="32">
    <stop stop-color="#f2c877"/><stop offset="1" stop-color="#7c9cff"/></linearGradient></defs></svg>`;

const NAV_CSS = `
.fh-nav{position:sticky;top:0;z-index:9999;backdrop-filter:saturate(140%) blur(12px);
  background:rgba(10,13,22,.72);border-bottom:1px solid #222c44;
  font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Inter,sans-serif;}
.fh-nav *{box-sizing:border-box;}
.fh-nav .fh-in{max-width:1080px;margin:0 auto;padding:12px 22px;display:flex;align-items:center;gap:22px;}
.fh-nav .fh-brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;color:#eef2fb;
  text-decoration:none;letter-spacing:-.01em;}
.fh-nav .fh-ln{display:flex;gap:20px;margin-left:auto;align-items:center;}
.fh-nav .fh-ln a{color:#8b97b4;font-size:14.5px;font-weight:500;text-decoration:none;transition:color .15s;}
.fh-nav .fh-ln a:hover{color:#eef2fb;}
.fh-nav .fh-ln a.on{color:#eef2fb;}
.fh-nav .fh-ln a.fh-cta{color:#0a0d16;background:linear-gradient(180deg,#f2c877,#e8b559);
  padding:7px 14px;border-radius:9px;font-weight:650;}
.fh-nav .fh-ln a.fh-cta:hover{filter:brightness(1.06);color:#0a0d16;}
@media(max-width:680px){.fh-nav .fh-ln{gap:14px;}.fh-nav .fh-ln a.fh-hide{display:none;}}
`;

function injectNav() {
  if (document.querySelector('.fh-nav')) return;
  // Remove any legacy hand-rolled nav so there is exactly one header on the page.
  document.querySelector('nav.nav')?.remove();

  const active = document.querySelector('script[data-page]')?.dataset.page || '';
  const style = document.createElement('style');
  style.textContent = NAV_CSS;
  document.head.appendChild(style);

  const links = LINKS.map(
    (l) => `<a href="${l.href}" class="fh-hide ${l.id === active ? 'on' : ''}">${l.label}</a>`
  ).join('');
  const nav = document.createElement('nav');
  nav.className = 'fh-nav';
  nav.innerHTML = `<div class="fh-in">
    <a class="fh-brand" href="./index.html">${MARK}<span>Freehold</span></a>
    <div class="fh-ln">${links}
      <a class="fh-hide" href="${GH}" target="_blank" rel="noopener">GitHub ↗</a>
      <a class="fh-cta" href="./passkey.html">Try the demo</a>
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
