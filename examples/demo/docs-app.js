// Freehold docs — client app. Renders the pre-built design docs (docs-data.js) ON the site, with a
// grouped sidebar, per-doc table of contents, hash routing, and search-as-you-type over the content.
import { GROUPS, DOCS } from './docs-data.js';

const $ = (s, r = document) => r.querySelector(s);
const el = (t, cls, html) => { const e = document.createElement(t); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const nav = $('#docnav'), content = $('#doc'), tocEl = $('#toc');
const q = $('#q'), results = $('#results');

// ---- sidebar nav ----
const linkFor = {};
for (const g of GROUPS) {
  nav.appendChild(el('div', 'docs-group', esc(g.name)));
  const ul = el('div', 'docs-links');
  for (const d of g.docs) {
    const a = el('a', 'docs-link', esc(d.label));
    a.href = `#${d.slug}`;
    linkFor[d.slug] = a;
    ul.appendChild(a);
  }
  nav.appendChild(ul);
}

// ---- render a doc ----
let current = null;
function renderDoc(slug, headingId) {
  const d = DOCS[slug];
  if (!d) return;
  current = slug;
  content.innerHTML = `<div class="doc-head"><span class="doc-group">${esc(d.group)}</span>`
    + `<h1>${esc(d.title)}</h1>${d.status ? `<p class="doc-status">${esc(d.status)}</p>` : ''}</div>`
    + d.html;
  // TOC
  tocEl.innerHTML = '';
  if (d.headings.length) {
    tocEl.appendChild(el('div', 'toc-title', 'On this page'));
    for (const h of d.headings) {
      const a = el('a', `toc-link lvl-${h.level}`, esc(h.text));
      a.href = `#${slug}/${h.id}`;
      tocEl.appendChild(a);
    }
  }
  for (const s in linkFor) linkFor[s].classList.toggle('on', s === slug);
  document.title = `${d.title} — Freehold docs`.replace(/—/g, '·');
  if (headingId) {
    const t = document.getElementById(headingId);
    if (t) { t.scrollIntoView(); return; }
  }
  content.parentElement.scrollTo(0, 0);
  window.scrollTo(0, 0);
}

// ---- routing ----
function route() {
  const h = decodeURIComponent(location.hash.replace(/^#/, ''));
  const [slug, headingId] = h.split('/');
  if (slug && DOCS[slug]) renderDoc(slug, headingId);
  else renderDoc(GROUPS[0].docs[0].slug);
}
window.addEventListener('hashchange', () => { closeResults(); route(); });

// ---- search ----
const INDEX = Object.values(DOCS).map((d) => ({
  slug: d.slug, title: d.title, label: d.label, group: d.group,
  hay: (d.title + ' ' + d.label + ' ' + d.text).toLowerCase(),
  text: d.text, headings: d.headings,
}));

function search(query) {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return [];
  const out = [];
  for (const doc of INDEX) {
    let score = 0;
    for (const t of terms) {
      const inTitle = (doc.title + ' ' + doc.label).toLowerCase().includes(t);
      const n = doc.hay.split(t).length - 1;
      if (!n && !inTitle) { score = -1; break; }        // every term must appear
      score += (inTitle ? 20 : 0) + Math.min(n, 8);
    }
    if (score > 0) {
      // snippet around the first body hit of the first term
      const lc = doc.text.toLowerCase();
      let i = -1; for (const t of terms) { i = lc.indexOf(t); if (i >= 0) break; }
      let snip = '';
      if (i >= 0) {
        const start = Math.max(0, i - 60), end = Math.min(doc.text.length, i + 90);
        snip = (start ? '… ' : '') + doc.text.slice(start, end) + (end < doc.text.length ? ' …' : '');
      } else snip = doc.text.slice(0, 130) + ' …';
      // best matching heading (for a deep link)
      let hid = '';
      for (const hd of doc.headings) { if (terms.some((t) => hd.text.toLowerCase().includes(t))) { hid = hd.id; break; } }
      out.push({ doc, score, snip, hid });
    }
  }
  return out.sort((a, b) => b.score - a.score).slice(0, 10);
}

function hi(text, terms) {
  let s = esc(text);
  for (const t of terms) if (t) s = s.replace(new RegExp(`(${t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'ig'), '<mark>$1</mark>');
  return s;
}

let activeIdx = -1;
function renderResults(list, terms) {
  results.innerHTML = '';
  if (!list.length) { results.appendChild(el('div', 'res-empty', 'No matches')); results.hidden = false; return; }
  list.forEach((r, idx) => {
    const a = el('a', 'res', '');
    a.href = `#${r.doc.slug}${r.hid ? '/' + r.hid : ''}`;
    a.innerHTML = `<span class="res-group">${esc(r.doc.group)}</span>`
      + `<span class="res-title">${hi(r.doc.title, terms)}</span>`
      + `<span class="res-snip">${hi(r.snip, terms)}</span>`;
    a.addEventListener('click', () => closeResults());
    results.appendChild(a);
  });
  activeIdx = -1;
  results.hidden = false;
}
function closeResults() { results.hidden = true; activeIdx = -1; }

let t0;
q.addEventListener('input', () => {
  clearTimeout(t0);
  t0 = setTimeout(() => {
    const query = q.value.trim();
    if (!query) { closeResults(); return; }
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    renderResults(search(query), terms);
  }, 90);
});
q.addEventListener('keydown', (e) => {
  const items = [...results.querySelectorAll('.res')];
  if (e.key === 'Escape') { closeResults(); q.blur(); }
  else if (e.key === 'ArrowDown' && items.length) { e.preventDefault(); activeIdx = Math.min(activeIdx + 1, items.length - 1); items.forEach((it, i) => it.classList.toggle('on', i === activeIdx)); }
  else if (e.key === 'ArrowUp' && items.length) { e.preventDefault(); activeIdx = Math.max(activeIdx - 1, 0); items.forEach((it, i) => it.classList.toggle('on', i === activeIdx)); }
  else if (e.key === 'Enter') { const pick = items[activeIdx] || items[0]; if (pick) { location.hash = pick.getAttribute('href').slice(1); closeResults(); } }
});
document.addEventListener('click', (e) => { if (!results.contains(e.target) && e.target !== q) closeResults(); });
document.addEventListener('keydown', (e) => { if (e.key === '/' && document.activeElement !== q) { e.preventDefault(); q.focus(); } });

route();
