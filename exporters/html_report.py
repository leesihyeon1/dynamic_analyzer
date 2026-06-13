"""
HTML 동적 분석 보고서 생성 (다크 테마)
"""
from __future__ import annotations

import hashlib
import html as _html
import json as _json
from datetime import datetime
from pathlib import Path

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; line-height: 1.6; }
.container { max-width: 1300px; margin: 0 auto; padding: 2rem; }
h1 { font-size: 1.8rem; color: #58a6ff; margin-bottom: 0.25rem; }
h2 { font-size: 1.15rem; color: #79c0ff; margin: 2rem 0 0.75rem;
     border-bottom: 1px solid #30363d; padding-bottom: 0.4rem; }
h3 { font-size: 0.95rem; color: #d2a8ff; margin: 1rem 0 0.4rem; }
.subtitle { color: #8b949e; font-size: 0.9rem; margin-bottom: 2rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
th { background: #161b22; color: #8b949e; text-align: left;
     padding: 0.5rem 0.75rem; font-weight: 600; white-space: nowrap; }
td { padding: 0.4rem 0.75rem; border-bottom: 1px solid #21262d;
     word-break: break-all; vertical-align: top; }
tr:hover td { background: #161b22; }
.badge { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 9999px;
         font-size: 0.72rem; font-weight: 600; white-space: nowrap; }
.badge-red    { background: #3d1f1f; color: #ff7b72; }
.badge-orange { background: #3d2a1f; color: #ffa657; }
.badge-yellow { background: #3d361f; color: #e3b341; }
.badge-green  { background: #1f3d2a; color: #56d364; }
.badge-blue   { background: #1f2d3d; color: #79c0ff; }
.badge-purple { background: #2d1f3d; color: #d2a8ff; }
.badge-gray   { background: #21262d; color: #8b949e; }
.alert { padding: 0.75rem 1rem; border-radius: 6px; margin: 0.75rem 0; font-size: 0.875rem; }
.alert-danger  { background: #3d1f1f; border-left: 3px solid #ff7b72; }
.alert-warning { background: #3d2a1f; border-left: 3px solid #ffa657; }
.alert-info    { background: #1f2d3d; border-left: 3px solid #79c0ff; }
.alert-success { background: #1f3d2a; border-left: 3px solid #56d364; }
.mono  { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 0.78rem; }
code   { background: #161b22; padding: 0.1rem 0.3rem; border-radius: 4px;
         font-family: monospace; font-size: 0.8rem; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
.card  { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.25rem; }
.kv td:first-child { color: #8b949e; width: 180px; font-weight: 500; white-space: nowrap; }
.tactic-tag { font-size: 0.68rem; color: #8b949e; margin-left: 0.4rem; }
.ev-file     { color: #79c0ff; }
.ev-registry { color: #d2a8ff; }
.ev-process  { color: #ffa657; }
.ev-network  { color: #56d364; }
.pg-wrap{display:flex;align-items:center;gap:.75rem;padding:.6rem 0;flex-wrap:wrap;border-top:1px solid #21262d;margin-top:.25rem}
.pg-info{color:#8b949e;font-size:.78rem;flex:1}
.pg-btns{display:flex;gap:.2rem;flex-wrap:wrap}
.pg-btn{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;padding:.18rem .52rem;font-size:.78rem;cursor:pointer;min-width:28px}
.pg-btn:hover{background:#30363d}
.pg-active{background:#1f6feb!important;color:#fff!important;border-color:#1f6feb!important}
.pg-ellipsis{color:#8b949e;padding:0 .2rem;line-height:2;font-size:.78rem}
.srch-wrap{margin:.5rem 0 .35rem}
.srch-input{background:#0d1117;border:1px solid #30363d;border-radius:6px;
            color:#e6edf3;font-size:.82rem;padding:.32rem .65rem;
            width:min(100%,360px);outline:none;transition:border-color .15s}
.srch-input:focus{border-color:#58a6ff}
.srch-input::placeholder{color:#484f58}
.tabs{display:flex;gap:0;border-bottom:1px solid #30363d;margin-bottom:1.5rem;overflow-x:auto;}
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;color:#8b949e;
         padding:.6rem 1.1rem;cursor:pointer;font-size:.85rem;white-space:nowrap;transition:color .15s;}
.tab-btn:hover{color:#e6edf3;background:rgba(255,255,255,.03);}
.tab-btn.active{color:#58a6ff;border-bottom-color:#58a6ff;font-weight:600;}
.tab-panel{display:none;}
.tab-panel.active{display:block;animation:fadeIn .18s ease;}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.tbadge{display:inline-flex;align-items:center;justify-content:center;min-width:1.6rem;
        height:1.35rem;padding:0 .45rem;border-radius:9999px;font-size:.72rem;font-weight:700;
        line-height:1;margin-left:.3rem;}
.tbadge-red   {background:#3d1f1f;color:#ff7b72;}
.tbadge-orange{background:#3d2a1f;color:#ffa657;}
.tbadge-green {background:#1f3d2a;color:#56d364;}
.tbadge-blue  {background:#1f2d3d;color:#79c0ff;}
.tbadge-gray  {background:#21262d;color:#8b949e;}
/* ── Hunt Tab ── */
.hunt-box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin-bottom:1rem}
.hunt-row{display:flex;gap:.6rem;align-items:center}
.hunt-input{flex:1;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;
            font-size:.9rem;padding:.46rem .85rem;outline:none;transition:border-color .15s}
.hunt-input:focus{border-color:#58a6ff}
.hunt-input::placeholder{color:#484f58}
.hunt-btn{background:#1f6feb;color:#fff;border:none;border-radius:6px;padding:.44rem 1.2rem;
          font-size:.88rem;font-weight:600;cursor:pointer;white-space:nowrap;transition:background .15s}
.hunt-btn:hover{background:#388bfd}
.hunt-btn:disabled{background:#1d2d40;color:#484f58;cursor:not-allowed}
.hunt-hint{color:#8b949e;font-size:.76rem;margin-top:.4rem;min-height:1.2em}
.hunt-type-tag{background:#21262d;color:#79c0ff;border-radius:4px;padding:.1rem .45rem;
               font-size:.73rem;font-weight:600}
.hunt-quick{display:flex;flex-wrap:wrap;gap:.35rem;align-items:center;
            margin-top:.75rem;padding-top:.75rem;border-top:1px solid #21262d}
.hunt-qlabel{color:#8b949e;font-size:.73rem;white-space:nowrap;margin-right:.15rem}
.hunt-qchip{background:#21262d;border:1px solid #30363d;border-radius:9999px;color:#c9d1d9;
            font-size:.71rem;padding:.12rem .6rem;cursor:pointer;transition:background .12s,color .12s;
            font-family:'Cascadia Code','Consolas',monospace}
.hunt-qchip:hover{background:#30363d;color:#e6edf3}
.hunt-qchip.ip    {border-color:#3d2a1f;color:#ffa657}
.hunt-qchip.domain{border-color:#1f2d3d;color:#79c0ff}
.hunt-qchip.hash  {border-color:#2d1f3d;color:#d2a8ff}
.hunt-svcs{display:flex;gap:.45rem;flex-wrap:wrap;margin-bottom:1rem}
.svc-badge{display:inline-flex;align-items:center;gap:.3rem;padding:.22rem .75rem;border-radius:6px;
           font-size:.76rem;font-weight:600;border:1px solid transparent;transition:all .2s}
.svc-badge.idle   {background:#161b22;border-color:#30363d;color:#8b949e}
.svc-badge.loading{background:#1f2d3d;border-color:#1f6feb;color:#79c0ff;animation:svcPulse .9s ease infinite}
.svc-badge.found  {background:#3d1f1f;border-color:#ff7b72;color:#ff7b72}
.svc-badge.clean  {background:#1f3d2a;border-color:#56d364;color:#56d364}
.svc-badge.error  {background:#21262d;border-color:#484f58;color:#8b949e}
@keyframes svcPulse{0%,100%{opacity:1}50%{opacity:.45}}
.hunt-card{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:.85rem;overflow:hidden}
.hunt-card.found .hunt-card-head{border-left:3px solid #ff7b72}
.hunt-card.clean .hunt-card-head{border-left:3px solid #56d364}
.hunt-card.error .hunt-card-head{border-left:3px solid #484f58}
.hunt-card-head{display:flex;align-items:center;justify-content:space-between;
                padding:.62rem 1rem;border-bottom:1px solid #21262d}
.hunt-card-title{font-weight:600;font-size:.88rem;display:flex;align-items:center;gap:.45rem}
.hunt-card-body{padding:.85rem 1rem}
.hunt-kv{font-size:.82rem;width:auto}
.hunt-kv td:first-child{color:#8b949e;width:130px;padding:.28rem .5rem .28rem 0;white-space:nowrap}
.hunt-kv td:last-child{padding:.28rem 0}
.hunt-tags{display:flex;flex-wrap:wrap;gap:.3rem;margin-top:.1rem}
.hunt-link{color:#58a6ff;font-size:.76rem;text-decoration:none}
.hunt-link:hover{text-decoration:underline}
.hunt-none{color:#8b949e;font-size:.83rem}
/* ── Process Tree ── */
.ptree{font-family:'Cascadia Code','Consolas',monospace;font-size:.82rem;
       background:#0d1117;border:1px solid #30363d;border-radius:8px;
       padding:1rem 1.25rem;margin-bottom:1.5rem}
.pt-wrap{margin-left:0}
.pt-children{padding-left:1.4rem;border-left:1px solid #21262d;margin-left:.5rem}
.pt-row{display:flex;align-items:baseline;gap:.4rem;padding:.22rem .4rem;
        border-radius:4px;flex-wrap:wrap;line-height:1.5}
.pt-row.pt-clickable{cursor:pointer}
.pt-row.pt-clickable:hover{background:#161b22}
.pt-arr{color:#484f58;font-size:.65rem;min-width:12px;flex-shrink:0;transition:transform .15s}
.pt-leaf{color:#30363d;font-size:.55rem;min-width:12px;flex-shrink:0}
.pt-name-new{color:#ffa657;font-weight:600}
.pt-name-existing{color:#8b949e}
.pt-name-suspicious{color:#ff7b72;font-weight:700}
.pt-name-sample{color:#e3b341;font-weight:700}
.pt-pid{color:#484f58;font-size:.73rem}
.pt-meta{color:#3d444d;font-size:.70rem;padding:.02rem 0 .05rem 1.6rem;
         word-break:break-all;line-height:1.35}
.pt-legend{display:flex;gap:1.2rem;font-size:.74rem;color:#8b949e;
           margin-bottom:.75rem;flex-wrap:wrap}
.pt-legend span{display:flex;align-items:center;gap:.3rem}
"""

_JS = """
function togglePT(id) {
  var el  = document.getElementById(id);
  var arr = document.getElementById('arr_' + id);
  if (!el) return;
  var hidden = el.style.display === 'none';
  el.style.display = hidden ? '' : 'none';
  if (arr) arr.textContent = hidden ? '▼' : '▶';
}
function expandAllPT() {
  document.querySelectorAll('.pt-children').forEach(function(el){el.style.display=''});
  document.querySelectorAll('.pt-arr').forEach(function(el){el.textContent='▼'});
}
function collapseAllPT() {
  document.querySelectorAll('.pt-children').forEach(function(el){el.style.display='none'});
  document.querySelectorAll('.pt-arr').forEach(function(el){el.textContent='▶'});
}

function setupTableControls(tableId, rowsPerPage) {
    var table = document.getElementById(tableId);
    if (!table) return;
    var allRows = Array.prototype.slice.call(table.rows, 1);
    if (allRows.length === 0) return;

    // 검색바 삽입
    var sw = document.createElement('div');
    sw.className = 'srch-wrap';
    var inp = document.createElement('input');
    inp.type = 'text';
    inp.className = 'srch-input';
    inp.placeholder = '행 검색…';
    sw.appendChild(inp);
    table.parentNode.insertBefore(sw, table);

    // 페이지네이션 컨테이너
    var pgDiv = document.createElement('div');
    pgDiv.className = 'pg-wrap';
    table.parentNode.insertBefore(pgDiv, table.nextSibling);

    var cur = 1;
    var filtered = allRows.slice();

    function renderPage(page) {
        cur = page;
        var total = filtered.length;
        var rpp = rowsPerPage > 0 ? rowsPerPage : total;
        var totalPages = Math.max(1, Math.ceil(total / rpp));
        if (cur > totalPages) cur = totalPages;

        allRows.forEach(function(r) { r.style.display = 'none'; });
        var start = (cur - 1) * rpp;
        filtered.slice(start, start + rpp).forEach(function(r) { r.style.display = ''; });

        pgDiv.innerHTML = '';
        var info = document.createElement('span');
        info.className = 'pg-info';
        var q = inp.value.trim();
        if (q) {
            info.textContent = total + '건 일치 (전체 ' + allRows.length + '행)';
        } else if (total === 0) {
            info.textContent = '0행';
        } else if (total <= rpp) {
            info.textContent = total + '행';
        } else {
            info.textContent = (start + 1) + '–' + Math.min(start + rpp, total) + ' / ' + total + '행';
        }
        pgDiv.appendChild(info);

        if (total > rpp) {
            var btns = document.createElement('span');
            btns.className = 'pg-btns';
            function mkBtn(p, label, active) {
                var b = document.createElement('button');
                b.textContent = label !== undefined ? label : p;
                b.className = 'pg-btn' + (active ? ' pg-active' : '');
                b.onclick = function() { renderPage(p); };
                btns.appendChild(b);
            }
            function mkEll() {
                var s = document.createElement('span');
                s.className = 'pg-ellipsis'; s.textContent = '…';
                btns.appendChild(s);
            }
            if (cur > 1) mkBtn(cur - 1, '‹');
            var pages = [1];
            for (var p = Math.max(2, cur - 2); p <= Math.min(totalPages - 1, cur + 2); p++) pages.push(p);
            if (totalPages > 1) pages.push(totalPages);
            pages = pages.filter(function(v, i, a) { return a.indexOf(v) === i; });
            var last = 0;
            pages.forEach(function(p) {
                if (p - last > 1) mkEll();
                mkBtn(p, p, p === cur);
                last = p;
            });
            if (cur < totalPages) mkBtn(cur + 1, '›');
            pgDiv.appendChild(btns);
        }
    }

    inp.addEventListener('input', function() {
        var q = inp.value.toLowerCase();
        filtered = q ? allRows.filter(function(r) {
            return r.textContent.toLowerCase().indexOf(q) !== -1;
        }) : allRows.slice();
        renderPage(1);
    });

    renderPage(1);
}
document.addEventListener('DOMContentLoaded', function () {
    var btns   = document.querySelectorAll('.tab-btn');
    var panels = document.querySelectorAll('.tab-panel');
    btns.forEach(function (btn) {
        btn.addEventListener('click', function () {
            btns.forEach(function(b){ b.classList.remove('active'); });
            panels.forEach(function(p){ p.classList.remove('active'); });
            btn.classList.add('active');
            document.getElementById(btn.dataset.tab).classList.add('active');
        });
    });
});

// ════════════════════════════════════════════════
//  Hunt Tab — abuse.ch 실시간 조회
// ════════════════════════════════════════════════

var _SVC_NAMES = {
    mb:    '📦 MalwareBazaar',
    tf:    '🎯 ThreatFox',
    uh:    '🌐 URLhaus',
    feodo: '👾 Feodo Tracker'
};

// ── 릴레이 fetch 헬퍼 ─────────────────────────────────────────────────
// HUNT_CFG.relay_port 가 설정된 경우 로컬 릴레이(Python)를 통해 요청합니다.
// 릴레이 실패 시 abuse.ch 직접 호출로 폴백합니다.
async function _relayFetch(svcKey, directUrl, options) {
    if (HUNT_CFG.relay_port) {
        var relayUrl = 'http://127.0.0.1:' + HUNT_CFG.relay_port + '/hunt/relay/' + svcKey;
        try {
            var r = await fetch(relayUrl, options);
            if (r.ok || r.status === 502) return r;  // 502 = relay got upstream error, still JSON
        } catch(e) { /* 릴레이 없음 → 직접 요청 */ }
    }
    return fetch(directUrl, options);
}

function huntDetect(val) {
    val = (val || '').trim();
    if (!val) return null;
    // HUNT_CFG 에서 활성화된 서비스만 포함
    function _svcs(list) {
        return list.filter(function(id) {
            var svc = HUNT_CFG.services[id] || HUNT_CFG.services['uh_url'];
            // uh 는 uh_url / uh_host 두 키를 대표 — enabled 는 둘 중 하나가 켜져 있으면 활성
            if (id === 'uh') return (HUNT_CFG.services.uh_url  && HUNT_CFG.services.uh_url.enabled  !== false)
                                 || (HUNT_CFG.services.uh_host && HUNT_CFG.services.uh_host.enabled !== false);
            return svc && svc.enabled !== false;
        });
    }
    if (/^[a-fA-F0-9]{64}$/.test(val)) { var s1=_svcs(['mb','tf']); return s1.length?{type:'sha256',label:'SHA256',svcs:s1}:null; }
    if (/^[a-fA-F0-9]{40}$/.test(val)) { var s2=_svcs(['mb','tf']); return s2.length?{type:'sha1',  label:'SHA1',  svcs:s2}:null; }
    if (/^[a-fA-F0-9]{32}$/.test(val)) { var s3=_svcs(['mb','tf']); return s3.length?{type:'md5',   label:'MD5',   svcs:s3}:null; }
    if (/^\\d{1,3}(\\.\\d{1,3}){3}(:\\d+)?$/.test(val)) { var s4=_svcs(['tf','uh','feodo']); return s4.length?{type:'ip',    label:'IP 주소',svcs:s4}:null; }
    if (/^https?:\\/\\//i.test(val))    { var s5=_svcs(['uh','tf']);    return s5.length?{type:'url',   label:'URL',   svcs:s5}:null; }
    if (val.indexOf('.') > 0 && !/\\s/.test(val)) { var s6=_svcs(['tf','uh']); return s6.length?{type:'domain',label:'도메인',svcs:s6}:null; }
    return null;
}

function huntInputChanged() {
    var val = document.getElementById('hunt-q').value;
    var hint = document.getElementById('hunt-hint');
    if (!val.trim()) { hint.innerHTML = ''; return; }
    var d = huntDetect(val);
    hint.innerHTML = d
        ? '감지: <span class="hunt-type-tag">' + d.label + '</span> &nbsp;→ '
          + d.svcs.map(function(s){ return _SVC_NAMES[s]; }).join(' &nbsp; ')
        : '<span style="color:#ffa657">인식 불가 — SHA256·MD5·IP·도메인·URL 형식으로 입력</span>';
}

function huntQuick(val) {
    document.getElementById('hunt-q').value = val;
    huntInputChanged();
    huntSearch();
}

function huntSetSvc(id, state) {
    var el = document.getElementById('svc-' + id);
    if (el) el.className = 'svc-badge ' + state;
}

async function huntSearch() {
    var val = (document.getElementById('hunt-q').value || '').trim();
    if (!val) return;
    var det = huntDetect(val);
    if (!det) {
        document.getElementById('hunt-results').innerHTML =
            '<div class="alert alert-warning">인식할 수 없는 IOC 형식입니다.</div>';
        return;
    }
    var btn = document.getElementById('hunt-go');
    btn.disabled = true; btn.textContent = '조회 중…';

    ['mb','tf','uh','feodo'].forEach(function(s) {
        huntSetSvc(s, det.svcs.indexOf(s) >= 0 ? 'loading' : 'idle');
    });
    document.getElementById('hunt-results').innerHTML = '';

    var tasks = [];
    if (det.svcs.indexOf('mb')    >= 0) tasks.push(_huntMB(val, det.type));
    if (det.svcs.indexOf('tf')    >= 0) tasks.push(_huntTF(val));
    if (det.svcs.indexOf('uh')    >= 0) tasks.push(_huntUH(val, det.type));
    if (det.svcs.indexOf('feodo') >= 0) tasks.push(_huntFeodo(val.split(':')[0]));

    var settled = await Promise.allSettled(tasks);
    var html = settled.map(function(r) {
        return r.status === 'fulfilled' ? r.value : '';
    }).join('');
    document.getElementById('hunt-results').innerHTML = html ||
        '<div class="hunt-none">모든 서비스에서 결과 없음</div>';
    btn.disabled = false; btn.textContent = '🔍 Hunt';
}

// ── 카드 빌더 ──────────────────────────────────────────

function _card(svcKey, cls, badgeHtml, bodyHtml, link) {
    var linkHtml = link
        ? '<a href="' + link + '" target="_blank" class="hunt-link">↗ 페이지</a>' : '';
    return '<div class="hunt-card ' + cls + '">'
        + '<div class="hunt-card-head">'
        +   '<span class="hunt-card-title">' + _SVC_NAMES[svcKey] + '</span>'
        +   '<span>' + badgeHtml + ' ' + linkHtml + '</span>'
        + '</div>'
        + '<div class="hunt-card-body">' + bodyHtml + '</div>'
        + '</div>';
}

function _errCard(svcKey, err) {
    var msg = (err && err.message) || '알 수 없는 오류';
    if (/failed to fetch|networkerror|load failed/i.test(msg))
        msg = 'API 연결 실패 — 인터넷 연결 또는 CORS 확인 필요';
    return _card(svcKey, 'error',
        '<span class="badge badge-gray">오류</span>',
        '<span class="hunt-none">⚠ ' + msg + '</span>');
}

function _kv(rows) {
    return '<table class="hunt-kv"><tbody>'
        + rows.map(function(r) {
            return '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td></tr>';
          }).join('')
        + '</tbody></table>';
}

function _badge(text, color) {
    return '<span class="badge badge-' + color + '">' + text + '</span>';
}

// ── MalwareBazaar ──────────────────────────────────────

async function _huntMB(hash, type) {
    try {
        var body = new URLSearchParams();
        body.append('query', 'get_info');
        if      (type === 'md5')  body.append('md5_hash',  hash);
        else if (type === 'sha1') body.append('sha1_hash', hash);
        else                      body.append('hash',      hash);
        var r = await _relayFetch('mb', HUNT_CFG.services.mb.url, {method:'POST', body:body});
        var d = await r.json();
        if (d.query_status !== 'hash_found' || !d.data || !d.data.length) {
            huntSetSvc('mb', 'clean');
            return _card('mb', 'clean', _badge('미등록','green'),
                '<span class="hunt-none">MalwareBazaar에 등록된 샘플 없음</span>');
        }
        huntSetSvc('mb', 'found');
        var item = d.data[0];
        var tags = (item.tags || []).map(function(t) {
            return '<span class="badge badge-orange">' + t + '</span>';
        }).join(' ');
        var vtCount = item.vendor_intel ? Object.keys(item.vendor_intel).length : 0;
        return _card('mb', 'found', _badge('등록됨','red'),
            _kv([
                ['파일명',   item.file_name  || '-'],
                ['서명',     '<strong>' + (item.signature || '미분류') + '</strong>'],
                ['파일 유형', item.file_type  || '-'],
                ['크기',     item.file_size ? item.file_size.toLocaleString() + ' bytes' : '-'],
                ['태그',     tags ? '<div class="hunt-tags">' + tags + '</div>' : '-'],
                ['AV 탐지',  vtCount ? vtCount + '개 엔진' : '-'],
                ['최초 발견', item.first_seen || '-'],
                ['최종 발견', item.last_seen  || '-'],
            ]),
            'https://bazaar.abuse.ch/sample/' + hash + '/');
    } catch(e) { huntSetSvc('mb', 'error'); return _errCard('mb', e); }
}

// ── ThreatFox ──────────────────────────────────────────

async function _huntTF(ioc) {
    try {
        var r = await _relayFetch('tf', HUNT_CFG.services.tf.url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({query: 'search_ioc', search_term: ioc})
        });
        var d = await r.json();
        if (d.query_status !== 'ok' || !d.data || !d.data.length) {
            huntSetSvc('tf', 'clean');
            return _card('tf', 'clean', _badge('미등록','green'),
                '<span class="hunt-none">ThreatFox에 등록된 IOC 없음</span>');
        }
        huntSetSvc('tf', 'found');
        var rows = d.data.slice(0, 15).map(function(item) {
            var conf = item.confidence_level || 0;
            var cc = conf >= 75 ? 'red' : conf >= 50 ? 'orange' : 'yellow';
            return '<tr>'
                + '<td class="mono">' + (item.ioc || '-') + '</td>'
                + '<td>' + (item.ioc_type || '-') + '</td>'
                + '<td><strong>' + (item.malware || '-') + '</strong></td>'
                + '<td>' + _badge(conf + '%', cc) + '</td>'
                + '<td style="color:#8b949e;font-size:.75rem">' + (item.first_seen || '-') + '</td>'
                + '</tr>';
        }).join('');
        return _card('tf', 'found', _badge(d.data.length + '건', 'red'),
            '<table><tr><th>IOC</th><th>유형</th><th>악성코드</th><th>신뢰도</th><th>최초 발견</th></tr>'
            + rows + '</table>',
            'https://threatfox.abuse.ch/browse.php?search=ioc%3A' + encodeURIComponent(ioc));
    } catch(e) { huntSetSvc('tf', 'error'); return _errCard('tf', e); }
}

// ── URLhaus ────────────────────────────────────────────

async function _huntUH(ioc, type) {
    try {
        var isURL = (type === 'url');
        var ep = isURL
            ? HUNT_CFG.services.uh_url.url
            : HUNT_CFG.services.uh_host.url;
        var body = new URLSearchParams();
        body.append(isURL ? 'url' : 'host', ioc);
        var relayKey = isURL ? 'uh_url' : 'uh_host';
        var r = await _relayFetch(relayKey, ep, {method:'POST', body:body});
        var d = await r.json();
        var notFound = (d.query_status === 'no_results' || d.query_status === 'invalid_url'
                        || (!isURL && d.query_status !== 'is_host'));
        if (notFound) {
            huntSetSvc('uh', 'clean');
            return _card('uh', 'clean', _badge('미등록','green'),
                '<span class="hunt-none">URLhaus에 등록된 항목 없음</span>');
        }
        huntSetSvc('uh', 'found');
        var body2 = '';
        if (!isURL && d.urls && d.urls.length) {
            var bl = d.blacklists || {};
            body2 += _kv([
                ['Spamhaus DBL', bl.spamhaus_dbl || '-'],
                ['SURBL',        bl.surbl        || '-'],
            ]);
            var urows = d.urls.slice(0, 10).map(function(u) {
                var sc = u.url_status === 'online' ? 'red' : 'gray';
                return '<tr><td class="mono" style="font-size:.72rem">' + (u.url || '-') + '</td>'
                    + '<td>' + _badge(u.url_status || '-', sc) + '</td>'
                    + '<td style="color:#8b949e">' + (u.threat || '-') + '</td></tr>';
            }).join('');
            body2 += '<h3 style="margin-top:.7rem">연관 URL (' + d.urls.length + '건)</h3>'
                + '<table><tr><th>URL</th><th>상태</th><th>위협</th></tr>' + urows + '</table>';
        } else if (isURL) {
            var sc2 = d.url_status === 'online' ? 'red' : 'gray';
            body2 = _kv([
                ['상태',     _badge(d.url_status || '-', sc2)],
                ['위협',     d.threat    || '-'],
                ['호스트',   d.host      || '-'],
                ['등록일',   d.date_added|| '-'],
                ['태그',     (d.tags||[]).join(', ') || '-'],
            ]);
        }
        return _card('uh', 'found', _badge('등록됨','red'), body2,
            'https://urlhaus.abuse.ch/browse.php?search=' + encodeURIComponent(ioc));
    } catch(e) { huntSetSvc('uh', 'error'); return _errCard('uh', e); }
}

// ── Feodo Tracker ──────────────────────────────────────

async function _huntFeodo(ip) {
    try {
        var r = await _relayFetch('feodo', HUNT_CFG.services.feodo.url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({host: ip})
        });
        var d = await r.json();
        if (!d || d.result !== 'known_tracker') {
            huntSetSvc('feodo', 'clean');
            return _card('feodo', 'clean', _badge('미등록','green'),
                '<span class="hunt-none">Feodo Tracker 봇넷 C2 목록에 없음</span>');
        }
        huntSetSvc('feodo', 'found');
        var sc = d.status === 'online' ? 'red' : 'gray';
        return _card('feodo', 'found', _badge('C2 등록됨','red'),
            _kv([
                ['악성코드',  '<strong>' + (d.malware || '-') + '</strong>'],
                ['상태',      _badge(d.status || '-', sc)],
                ['국가',      d.country || '-'],
                ['ASN',       d.asn     || '-'],
                ['최초 발견', d.first_seen || '-'],
                ['최종 발견', d.last_seen  || '-'],
            ]),
            'https://feodotracker.abuse.ch/browse/host/' + ip + '/');
    } catch(e) { huntSetSvc('feodo', 'error'); return _errCard('feodo', e); }
}
"""

_PG_INIT = """<script>
window.addEventListener('load', function() {
  var tbls = [
    'tbl-mitre','tbl-process',
    'tbl-file',
    'tbl-reg-diff','tbl-reg-procmon',
    'tbl-net-beacon','tbl-net-tls','tbl-net-conn',
    'tbl-net-dga','tbl-net-dns','tbl-net-http',
    'tbl-net-smtp','tbl-net-ftp',
    'tbl-ioc-ip','tbl-ioc-domain','tbl-ioc-file','tbl-ioc-reg','tbl-ioc-url'
  ];
  tbls.forEach(function(id) { setupTableControls(id, 100); });
});
</script>"""

_TACTIC_COLOR = {
    "Execution":        "red",
    "Persistence":      "orange",
    "Privilege Escalation": "red",
    "Defense Evasion":  "yellow",
    "Command and Control": "purple",
    "Exfiltration":     "orange",
    "Impact":           "red",
}

_SOURCE_COLOR = {
    "로컬룰":      "gray",
    "CAPA":       "blue",
    "VirusTotal": "green",
}


def _source_badges(sources: list) -> str:
    """출처 배지 HTML 반환. 빈 리스트면 '로컬룰' 배지 기본 표시."""
    if not sources:
        sources = ["로컬룰"]
    return " ".join(
        f"<span class='badge badge-{_SOURCE_COLOR.get(s, 'gray')}'>{_e(s)}</span>"
        for s in sources
    )

def _b(text: str, color: str = "gray") -> str:
    return f'<span class="badge badge-{color}">{_html.escape(str(text))}</span>'

def _e(text: str) -> str:
    return _html.escape(str(text))

def _tb(val, color: str = "gray") -> str:
    """탭 배지 (숫자 0 이나 빈 값이면 생략)"""
    if not val:
        return ""
    return f'<span class="tbadge tbadge-{color}">{_html.escape(str(val))}</span>'

def _trunc_notice(total: int, shown: int) -> str:
    """total > shown 일 때 잘림 안내 배너를 반환합니다."""
    if total <= shown:
        return ""
    return (
        f"<p class='alert alert-info' "
        f"style='font-size:.8rem;padding:.45rem .85rem;margin-bottom:.55rem'>"
        f"📋 총 <strong>{total:,}건</strong> 중 <strong>{shown:,}건</strong>만 표시됩니다"
        f" &nbsp;—&nbsp; 전체 데이터는 <code>_dynamic_report.json</code>을 확인하세요."
        f"</p>"
    )


def _ext_integration_status_html(result) -> str:
    """CAPA / VirusTotal 연동 상태 패널 HTML 반환."""
    tu = getattr(result, "tools_used", {}) or {}
    capa_status = tu.get("capa", "")
    vt_status   = tu.get("virustotal", "")

    if not capa_status and not vt_status:
        return ""

    def _chip(label: str, status_str: str) -> str:
        if not status_str:
            return ""
        ok   = "건 기여" in status_str
        warn = any(x in status_str for x in ("비활성", "API 키", "미설치", "비PE", "결과 없음", "오류", "건너뜀"))
        color = "#56d364" if ok else ("#ffa657" if warn else "#8b949e")
        icon  = "✅" if ok else ("⚠" if warn else "ℹ")
        return (
            f"<span style='display:inline-flex;align-items:center;gap:.35rem;"
            f"background:#161b22;border:1px solid #30363d;border-radius:6px;"
            f"padding:.25rem .7rem;font-size:.78rem;color:{color}'>"
            f"{icon}&nbsp;<b>{label}</b>&nbsp;—&nbsp;{_e(status_str)}</span>"
        )

    chips = " ".join(filter(None, [_chip("CAPA", capa_status), _chip("VirusTotal", vt_status)]))
    return (
        f"<div style='display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:.8rem;align-items:center'>"
        f"<span style='font-size:.75rem;color:#6e7681'>외부 연동:</span> {chips}"
        f"</div>"
    )


def _section_html(result) -> str:
    """MITRE ATT&CK 기법 테이블"""
    techs = result.behavior_report.techniques if result.behavior_report else []
    status_html = _ext_integration_status_html(result)
    if not techs:
        return status_html + "<p class='alert alert-success'>탐지된 MITRE 기법 없음</p>"
    rows = ""
    for t in techs:
        color = _TACTIC_COLOR.get(t.tactic, "gray")
        ref   = t.reference or f"https://attack.mitre.org/techniques/{t.technique_id.replace('.','/')}/"
        evidence_html = "".join(
            f"<div class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(ev[:120])}</div>"
            for ev in t.evidence[:5]
        )
        # sources 필드는 구버전 JSON 호환을 위해 getattr 사용
        src_badges = _source_badges(getattr(t, "sources", []) or [])
        rows += (
            f"<tr>"
            f"<td><a href='{_e(ref)}' target='_blank' style='color:#f97583;text-decoration:none'>"
            f"{_e(t.technique_id)}</a></td>"
            f"<td>{_e(t.technique_name)}</td>"
            f"<td>{_b(t.tactic, color)}</td>"
            f"<td style='white-space:nowrap'>{src_badges}</td>"
            f"<td>{evidence_html}</td>"
            f"</tr>"
        )
    return (
        status_html
        + "<table id='tbl-mitre'>"
        "<tr><th>ID</th><th>기법</th><th>전술</th><th>출처</th><th>근거 (최대 5건)</th></tr>"
        f"{rows}</table>"
    )


_FILE_OPS       = frozenset({"WriteFile", "DeleteFile", "RenameFile", "SetEndOfFile"})
_FILE_OPS_CHAIN = frozenset({"WriteFile", "DeleteFile", "RenameFile", "SetEndOfFile", "CreateFile"})
_FILE_LIMIT = 2000

def _file_events_html(result) -> tuple[str, int]:
    """(HTML 문자열, 실제 이벤트 총 개수) 반환."""
    from parsers.procmon_csv import EventCategory

    # 악성 체인 PID — 해당 프로세스는 CreateFile(열기/생성)까지 전부 표시
    chain_pids: set[int] = {p.pid for p in _compute_display_procs(result)[0]}

    events = [
        e for e in result.filtered_events
        if e.category == EventCategory.FILE
        and e.operation in (_FILE_OPS_CHAIN if e.pid in chain_pids else _FILE_OPS)
    ]
    total = len(events)
    if not events:
        return "<p class='alert alert-success'>파일 시스템 이벤트 없음</p>", 0

    rows = ""
    op_color = {
        "WriteFile": "blue", "DeleteFile": "red",
        "RenameFile": "yellow", "SetEndOfFile": "gray", "CreateFile": "purple",
    }
    for e in events[:_FILE_LIMIT]:
        detail_str = (e.detail or "").strip()[:160]
        detail_html = (
            f"<div style='color:#6e7681;font-size:0.68rem;margin-top:.15rem'>{_e(detail_str)}</div>"
            if detail_str else ""
        )
        rows += (
            f"<tr>"
            f"<td class='mono' style='color:#8b949e;white-space:nowrap'>{_e(e.time_str[:12])}</td>"
            f"<td class='mono'>{_e(e.process)} <span style='color:#8b949e'>({e.pid})</span></td>"
            f"<td>{_b(e.operation, op_color.get(e.operation,'gray'))}</td>"
            f"<td class='mono ev-file'>{_e(e.path[:120])}{detail_html}</td>"
            f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(e.result)}</td>"
            f"</tr>"
        )
    html = (
        _trunc_notice(total, _FILE_LIMIT)
        + "<table id='tbl-file'><tr><th>시각</th><th>프로세스</th><th>작업</th><th>경로</th><th>결과</th></tr>"
        + rows + "</table>"
    )
    return html, total


def _registry_events_html(result) -> str:
    from parsers.procmon_csv import EventCategory
    _REG_OPS = ("RegSetValue", "RegCreateKey", "RegDeleteValue", "RegDeleteKey")
    events = [e for e in result.filtered_events if e.category == EventCategory.REGISTRY
              and e.operation in _REG_OPS]
    reg_diff = result.registry_diff
    added    = reg_diff.get("added", [])
    modified = reg_diff.get("modified", [])

    parts = []

    _REG_DIFF_LIMIT = 500
    _REG_EV_LIMIT   = 3000

    # Regshot 0건이지만 ProcMon 이벤트가 존재할 때 불일치 경고
    if not (added or modified) and events:
        parts.append(
            "<p class='alert alert-warning'>"
            "<b>⚠ Regshot 비교: 변경 없음</b>"
            f" &nbsp;·&nbsp; ProcMon 레지스트리 이벤트: <b>{len(events):,}건</b><br>"
            "<span style='font-size:.82rem'>가능한 원인: "
            "① 악성코드가 분석 종료 전 레지스트리를 원상복구 &nbsp;"
            "② 일시적 쓰기(쓰기 즉시 삭제) &nbsp;"
            "③ Regshot 캡처 범위 밖 하이브(예: HKCU 와 별개의 ntuser.dat)"
            "</span></p>"
        )

    # RegShot diff
    if added or modified:
        total_diff = len(added) + len(modified)
        rows = ""
        for k, n, v in added[:_REG_DIFF_LIMIT]:
            rows += (f"<tr><td>{_b('추가','green')}</td>"
                     f"<td class='mono ev-registry'>{_e(k)}</td>"
                     f"<td class='mono'>{_e(n)}</td>"
                     f"<td class='mono' style='color:#8b949e'>{_e(str(v)[:80])}</td></tr>")
        for k, n, o, nw in modified[:_REG_DIFF_LIMIT]:
            rows += (f"<tr><td>{_b('변경','orange')}</td>"
                     f"<td class='mono ev-registry'>{_e(k)}</td>"
                     f"<td class='mono'>{_e(n)}</td>"
                     f"<td class='mono' style='color:#8b949e'>{_e(str(nw)[:80])}</td></tr>")
        parts.append(
            "<h3>레지스트리 스냅샷 비교 (Regshot)</h3>"
            + _trunc_notice(total_diff, _REG_DIFF_LIMIT)
            + "<table id='tbl-reg-diff'><tr><th>변경</th><th>키 경로</th><th>값 이름</th><th>데이터</th></tr>"
            + f"{rows}</table>"
        )

    # ProcMon 이벤트
    if events:
        rows = ""
        for e in events[:_REG_EV_LIMIT]:
            rows += (
                f"<tr>"
                f"<td class='mono' style='color:#8b949e;white-space:nowrap'>{_e(e.time_str[:12])}</td>"
                f"<td class='mono'>{_e(e.process)}</td>"
                f"<td>{_b(e.operation,'purple')}</td>"
                f"<td class='mono ev-registry'>{_e(e.path[:100])}</td>"
                f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(e.detail[:60])}</td>"
                f"</tr>"
            )
        parts.append(
            "<h3>ProcMon 레지스트리 이벤트</h3>"
            + _trunc_notice(len(events), _REG_EV_LIMIT)
            + "<table id='tbl-reg-procmon'><tr><th>시각</th><th>프로세스</th><th>작업</th><th>키 경로</th><th>상세</th></tr>"
            + f"{rows}</table>"
        )

    return "\n".join(parts) if parts else "<p class='alert alert-success'>레지스트리 변경 없음</p>"


def _fmt_bytes(n: int) -> str:
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f} MB"
    if n >= 1_000:
        return f"{n/1_000:.1f} KB"
    return f"{n} B"


def _proc_cell(procs: list[str]) -> str:
    """프로세스 목록 → <td> HTML. 빈 경우 회색 '-' 반환."""
    if procs:
        return "<td>" + "<br>".join(
            f"<span class='ev-process mono' style='font-size:0.72rem'>{_e(p)}</span>"
            for p in procs[:3]
        ) + "</td>"
    return "<td style='color:#8b949e'>-</td>"


def _network_html(result) -> str:
    pcap = result.pcap_result
    if not pcap:
        return "<p class='alert alert-info'>tshark 캡처 없음</p>"

    # ── 공통 조회 테이블 (모든 섹션에서 공유) ─────────────────────
    # DNS 응답 + TLS SNI → IP-to-domain 종합 매핑
    combined_domains: dict[str, list[str]] = {}
    for _ip, _doms in pcap.ip_to_domain.items():
        _lst = combined_domains.setdefault(_ip, [])
        for _d in _doms:
            if _d not in _lst:
                _lst.append(_d)
    for _t in getattr(pcap, "tls_info", []):
        if _t.dst_ip and _t.sni:
            _lst = combined_domains.setdefault(_t.dst_ip, [])
            if _t.sni not in _lst:
                _lst.append(_t.sni)

    # 호스트명 → IP 역매핑
    hostname_to_ips: dict[str, list[str]] = {}
    for _ip, _doms in combined_domains.items():
        for _d in _doms:
            hostname_to_ips.setdefault(_d.lower(), []).append(_ip)

    # 프로세스 매핑 룩업: (proto, dst_ip, dst_port) → 프로세스 목록
    # ip_proc_lookup: ip → 프로세스 목록 (포트 무관 — HTTP 호스트명 매핑용)
    pnmap = getattr(result, "process_network_map", [])
    proc_lookup: dict[tuple, list[str]] = {}
    ip_proc_lookup: dict[str, list[str]] = {}
    for _pn in pnmap:
        _label = f"{_pn.process} ({_pn.pid})"
        _key   = (_pn.proto.upper(), _pn.remote_ip, _pn.remote_port)
        proc_lookup.setdefault(_key, [])
        if _label not in proc_lookup[_key]:
            proc_lookup[_key].append(_label)
        _ip_lst = ip_proc_lookup.setdefault(_pn.remote_ip, [])
        if _label not in _ip_lst:
            _ip_lst.append(_label)
        for _mapped_ip in hostname_to_ips.get(_pn.remote_ip.lower(), []):
            _ip_key = (_pn.proto.upper(), _mapped_ip, _pn.remote_port)
            proc_lookup.setdefault(_ip_key, [])
            if _label not in proc_lookup[_ip_key]:
                proc_lookup[_ip_key].append(_label)
            _ip2_lst = ip_proc_lookup.setdefault(_mapped_ip, [])
            if _label not in _ip2_lst:
                _ip2_lst.append(_label)

    parts = []

    # ── 캡처 요약 ──────────────────────────────────────────────
    s = getattr(pcap, "summary", None)
    if s:
        parts.append(
            f"<div class='card' style='margin-bottom:1rem'>"
            f"<table class='kv'>"
            f"<tr><td>총 패킷</td><td>{s.total_packets:,}</td></tr>"
            f"<tr><td>외부 송신</td><td>{_fmt_bytes(s.total_bytes_out)}</td></tr>"
            f"<tr><td>수신</td><td>{_fmt_bytes(s.total_bytes_in)}</td></tr>"
            f"<tr><td>외부 고유 IP</td><td>{s.unique_dst_ips}</td></tr>"
            f"<tr><td>고유 도메인</td><td>{s.unique_domains}</td></tr>"
            f"</table></div>"
        )

    # ── 비콘 탐지 ──────────────────────────────────────────────
    beacons = getattr(pcap, "beacon_candidates", [])
    if beacons:
        rows = ""
        for b in beacons[:100]:
            b_procs = (proc_lookup.get(("TCP", b.dst_ip, b.dst_port), [])
                       or proc_lookup.get(("UDP", b.dst_ip, b.dst_port), []))
            rows += (
                f"<tr>"
                f"<td class='mono ev-network'>{_e(b.dst_ip)}</td>"
                f"<td class='mono'>{b.dst_port}</td>"
                f"<td>{b.count}회</td>"
                f"<td class='mono'>{b.interval_avg}s</td>"
                f"<td>{_b(f'지터 {b.jitter_ratio:.1%}', 'red' if b.jitter_ratio < 0.1 else 'orange')}</td>"
                + _proc_cell(b_procs) +
                f"</tr>"
            )
        parts.append(
            "<h3>🚨 비콘(Beaconing) 탐지</h3>"
            "<table id='tbl-net-beacon'><tr><th>목적지 IP</th><th>포트</th><th>횟수</th>"
            "<th>평균 간격</th><th>규칙성</th><th>프로세스</th></tr>"
            f"{rows}</table>"
        )

    # ── TLS SNI ────────────────────────────────────────────────
    tls_list = getattr(pcap, "tls_info", [])
    if tls_list:
        seen = {}
        for t in tls_list:
            if t.sni not in seen:
                seen[t.sni] = t
        _TLS_LIMIT = 500
        seen_vals  = list(seen.values())
        rows = ""
        for t in seen_vals[:_TLS_LIMIT]:
            t_procs = proc_lookup.get(("TCP", t.dst_ip, t.dst_port), [])
            rows += (
                f"<tr>"
                f"<td class='mono ev-network'>{_e(t.sni)}</td>"
                f"<td class='mono'>{_e(t.dst_ip)}</td>"
                f"<td class='mono'>{t.dst_port}</td>"
                + _proc_cell(t_procs) +
                f"</tr>"
            )
        parts.append(
            "<h3>🔒 TLS SNI (HTTPS 도메인)</h3>"
            + _trunc_notice(len(seen_vals), _TLS_LIMIT)
            + "<table id='tbl-net-tls'><tr><th>SNI 도메인</th><th>목적지 IP</th><th>포트</th><th>프로세스</th></tr>"
            + f"{rows}</table>"
        )

    # ── DGA / 의심 도메인 ──────────────────────────────────────
    susp_domains = getattr(pcap, "suspicious_domains", [])
    if susp_domains:
        rows = "".join(
            f"<tr><td class='mono' style='color:#ff7b72'>{_e(d)}</td></tr>"
            for d in susp_domains[:50]
        )
        parts.append(
            "<h3>⚠ DGA / 고엔트로피 도메인</h3>"
            f"<table id='tbl-net-dga'><tr><th>도메인</th></tr>{rows}</table>"
        )

    # ── 연결 목록 ──────────────────────────────────────────────
    if pcap.connections:
        _CONN_LIMIT = 1000
        sorted_conns = sorted(pcap.connections, key=lambda x: -x.bytes_out)
        rows = ""
        for c in sorted_conns[:_CONN_LIMIT]:
            ext = not _is_private_ip_str(c.dst_ip)
            ip_color = "ev-network" if ext else ""
            susp_badge = _b("!", "red") if c.suspicious_port else ""

            # 도메인 컬럼
            conn_doms = combined_domains.get(c.dst_ip, [])
            if conn_doms:
                primary = conn_doms[0]
                extra   = len(conn_doms) - 1
                dom_td  = (
                    f"<td class='mono ev-network' style='font-size:0.78rem'>{_e(primary)}"
                    + (f"&nbsp;<span style='color:#8b949e'>+{extra}</span>" if extra else "")
                    + "</td>"
                )
            else:
                dom_td = "<td style='color:#484f58'>-</td>"

            rows += (
                f"<tr>"
                f"<td>{_b(c.proto, 'blue')}</td>"
                f"<td class='mono'>{_e(c.src_ip)}</td>"
                f"<td class='mono {ip_color}'>{_e(c.dst_ip)}</td>"
                f"{dom_td}"
                f"<td class='mono'>{c.dst_port} {susp_badge}</td>"
                f"<td style='color:#8b949e'>{c.count}</td>"
                f"<td class='mono'>{_fmt_bytes(c.bytes_out)}</td>"
                + _proc_cell(proc_lookup.get((c.proto.upper(), c.dst_ip, c.dst_port), [])) +
                f"</tr>"
            )
        parts.append(
            "<h3>네트워크 연결 (송신량 순)</h3>"
            + _trunc_notice(len(pcap.connections), _CONN_LIMIT)
            + "<table id='tbl-net-conn'><tr><th>프로토콜</th><th>출발지 IP</th><th>목적지 IP</th>"
            "<th>도메인</th><th>포트</th><th>횟수</th><th>송신량</th><th>프로세스</th></tr>"
            + f"{rows}</table>"
        )

    # ── DNS 쿼리 ───────────────────────────────────────────────
    if pcap.dns_queries:
        _DNS_LIMIT   = 1000
        sorted_dns   = sorted(pcap.dns_queries, key=lambda x: -x.entropy)
        rows = ""
        for q in sorted_dns[:_DNS_LIMIT]:
            dns_procs: list[str] = []
            for rip in q.response_ips[:5]:
                for p in ip_proc_lookup.get(rip, []):
                    if p not in dns_procs:
                        dns_procs.append(p)
            rows += (
                f"<tr>"
                f"<td class='mono {'ev-network' if not q.suspicious else ''}"
                f"' style='{'color:#ff7b72' if q.suspicious else ''}'>{_e(q.name)}</td>"
                f"<td class='mono' style='color:#8b949e'>{_e(q.qtype)}</td>"
                f"<td class='mono' style='color:#8b949e'>{q.entropy:.2f}</td>"
                f"<td class='mono' style='color:#56d364;font-size:0.72rem'>"
                f"{_e(', '.join(q.response_ips[:3]))}</td>"
                f"{'<td>' + _b('DGA?','red') + '</td>' if q.suspicious else '<td></td>'}"
                + _proc_cell(dns_procs) +
                f"</tr>"
            )
        parts.append(
            "<h3>DNS 쿼리 (엔트로피 순)</h3>"
            + _trunc_notice(len(pcap.dns_queries), _DNS_LIMIT)
            + "<table id='tbl-net-dns'><tr><th>도메인</th><th>타입</th><th>엔트로피</th>"
            "<th>응답 IP</th><th>의심</th><th>프로세스</th></tr>"
            + f"{rows}</table>"
        )

    # ── HTTP 요청 ──────────────────────────────────────────────
    if pcap.http_requests:
        _HTTP_LIMIT = 500
        rows = ""
        for r in pcap.http_requests[:_HTTP_LIMIT]:
            h_procs: list[str] = []
            for hname in hostname_to_ips.get(r.host.lower(), []):
                for p in ip_proc_lookup.get(hname, []):
                    if p not in h_procs:
                        h_procs.append(p)
            rows += (
                f"<tr>"
                f"<td>{_b(r.method,'orange')}</td>"
                f"<td class='mono'>{_e(r.host)}</td>"
                f"<td class='mono ev-network'>{_e(r.path[:80])}</td>"
                f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(r.user_agent[:60])}</td>"
                f"<td class='mono'>{_fmt_bytes(r.content_length) if r.content_length else '-'}</td>"
                f"<td>{'🍪' if r.has_cookie else ''}</td>"
                + _proc_cell(h_procs) +
                f"</tr>"
            )
        parts.append(
            "<h3>HTTP 요청</h3>"
            + _trunc_notice(len(pcap.http_requests), _HTTP_LIMIT)
            + "<table id='tbl-net-http'><tr><th>메서드</th><th>호스트</th><th>경로</th>"
            "<th>User-Agent</th><th>Body</th><th>Cookie</th><th>프로세스</th></tr>"
            + f"{rows}</table>"
        )

    # ── SMTP C2 세션 (AgentTesla 등 자격증명 탈취 악성코드) ─────────
    smtp_sessions = getattr(pcap, "smtp_sessions", [])
    if smtp_sessions:
        rows = ""
        for s in smtp_sessions:
            auth_badge  = _b("AUTH", "red")   if s.has_auth else ""
            data_badge  = _b("DATA", "orange") if s.has_data else ""
            smtp_procs  = proc_lookup.get(("TCP", s.dst_ip, s.dst_port), [])
            rows += (
                f"<tr>"
                f"<td class='mono ev-network'>{_e(s.dst_ip)}</td>"
                f"<td class='mono'>{s.dst_port}</td>"
                f"<td class='mono'>{_e(s.ehlo_domain or '-')}</td>"
                f"<td class='mono'>{_e(s.mail_from or '-')}</td>"
                f"<td class='mono'>{_e(', '.join(s.rcpt_to) or '-')}</td>"
                f"<td class='mono'>{_e(s.auth_user or '-')}</td>"
                f"<td>{auth_badge} {data_badge}</td>"
                + _proc_cell(smtp_procs) +
                f"</tr>"
            )
        parts.append(
            "<h3 style='color:#ff7b72'>🚨 SMTP C2 세션</h3>"
            "<table id='tbl-net-smtp'><tr><th>C2 서버 IP</th><th>포트</th><th>EHLO 도메인</th>"
            "<th>발신자 (MAIL FROM)</th><th>수신자 (RCPT TO)</th>"
            "<th>AUTH 사용자명</th><th>플래그</th><th>프로세스</th></tr>"
            f"{rows}</table>"
        )

    # ── FTP C2 세션 ────────────────────────────────────────────
    ftp_sessions = getattr(pcap, "ftp_sessions", [])
    if ftp_sessions:
        rows = ""
        for s in ftp_sessions:
            auth_badge = _b("AUTH", "red") if s.has_auth else ""
            ftp_procs  = proc_lookup.get(("TCP", s.dst_ip, s.dst_port), [])
            rows += (
                f"<tr>"
                f"<td class='mono ev-network'>{_e(s.dst_ip)}</td>"
                f"<td class='mono'>{s.dst_port}</td>"
                f"<td class='mono'>{_e(s.username or '-')}</td>"
                f"<td class='mono'>{_e(', '.join(s.uploaded)  or '-')}</td>"
                f"<td class='mono'>{_e(', '.join(s.downloaded) or '-')}</td>"
                f"<td>{auth_badge}</td>"
                + _proc_cell(ftp_procs) +
                f"</tr>"
            )
        parts.append(
            "<h3 style='color:#ff7b72'>🚨 FTP C2 세션</h3>"
            "<table id='tbl-net-ftp'><tr><th>C2 서버 IP</th><th>포트</th><th>사용자명</th>"
            "<th>업로드 파일</th><th>다운로드 파일</th><th>플래그</th><th>프로세스</th></tr>"
            f"{rows}</table>"
        )

    return "\n".join(parts) if parts else "<p class='alert alert-success'>외부 네트워크 활동 없음</p>"


def _is_private_ip_str(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or (a == 172 and 16 <= b <= 31)
                or (a == 192 and b == 168) or a == 127)
    except Exception:
        return False



# 확장자 → 예상 호스트 앱 이름 매핑 (ShellExecute 모드 루트 씨드 탐색용)
_SHELL_HOST_MAP: dict[str, frozenset[str]] = {
    ".doc":  frozenset({"winword.exe"}), ".docx": frozenset({"winword.exe"}),
    ".docm": frozenset({"winword.exe"}), ".dot":  frozenset({"winword.exe"}),
    ".dotm": frozenset({"winword.exe"}), ".rtf":  frozenset({"winword.exe"}),
    ".xls":  frozenset({"excel.exe"}),  ".xlsx": frozenset({"excel.exe"}),
    ".xlsm": frozenset({"excel.exe"}),  ".xlt":  frozenset({"excel.exe"}),
    ".xltm": frozenset({"excel.exe"}),
    ".ppt":  frozenset({"powerpnt.exe"}), ".pptx": frozenset({"powerpnt.exe"}),
    ".pptm": frozenset({"powerpnt.exe"}),
    ".js":   frozenset({"wscript.exe", "cscript.exe"}),
    ".vbs":  frozenset({"wscript.exe", "cscript.exe"}),
    ".vbe":  frozenset({"wscript.exe", "cscript.exe"}),
    ".hta":  frozenset({"mshta.exe"}),
    ".ps1":  frozenset({"powershell.exe", "pwsh.exe"}),
    ".bat":  frozenset({"cmd.exe"}), ".cmd": frozenset({"cmd.exe"}),
    ".pdf":  frozenset({"acrord32.exe", "acrobat.exe",
                        "foxitpdfeditor.exe", "foxitreader.exe"}),
}


def _compute_display_procs(result):
    """정상·무관 프로세스를 제외한 신규 프로세스 목록과 제외 건수를 반환합니다.

    malware_chain 씨드 결정 전략 (우선순위 순):

    [EXE 모드] sample_pid를 루트로 자손 확장.
    [ShellExecute 모드] 샘플 확장자 → _SHELL_HOST_MAP으로 호스트 앱 PID를 루트로 자손 확장.
      예) .doc → winword.exe PID, .vbs → wscript.exe PID
    [폴백-1] 위 두 방법으로 씨드를 못 구한 경우:
      filtered_events에 이벤트가 있는 비WL 신규 프로세스를 씨드로 사용.
      (noise_filter를 통과한 WriteFile·TCP 등 실질 활동 프로세스)
    [폴백-2] ProcMon 미사용 등: 비WL 전체.

    ※ pe-sieve/HH 탐지 PID는 전략과 무관하게 항상 씨드에 포함.

    제외 조건: 악성 실행 체인 외부 AND 의심 탐지 없음 AND sample_pid 아님.
      EXE 모드에서는 pids_with_events를 추가 조건으로 적용해
      ReadFile 전용 백그라운드 프로세스(SearchFilterHost 등)를 제거.
    """
    try:
        from analysis.shellcode_analyzer import _SYSTEM_PROC_WHITELIST as _WL
    except Exception:
        _WL = frozenset()

    all_procs  = result.process_diff.get("new_processes", [])
    sample_pid = getattr(result, "sample_pid", None)

    # ── 분석 도구 PID 집합 (suspicious 판정에서 항상 제외) ────────────
    # HH/pe-sieve가 자기 자신을 탐지하는 FP를 방지.
    _TOOL_NAMES: frozenset[str] = frozenset({
        "hollows_hunter.exe", "hollows_hunter64.exe",
        "hollows-hunter.exe", "hollows-hunter64.exe",
        "pe-sieve.exe", "pe-sieve64.exe",
    })
    _tool_pids: set[int] = {p.pid for p in all_procs if p.name.lower() in _TOOL_NAMES}

    # ── 의심 PID 집합 ────────────────────────────────────────────────
    suspicious_pids: set[int] = set()
    for r in (getattr(result, "pe_sieve_results", None) or []):
        if not getattr(r, "error", False) and getattr(r, "suspicious", 0) > 0:
            suspicious_pids.add(r.pid)
    hh_r = getattr(result, "hh_result", None)
    if hh_r and not getattr(hh_r, "error", None):
        for pr in getattr(hh_r, "process_results", []):
            if getattr(pr, "suspicious", 0) > 0:
                suspicious_pids.add(pr.pid)

    # 분석 도구 자체는 의심 목록에서 제거
    suspicious_pids -= _tool_pids

    # ── pe-sieve 이상없음(정상 판정) PID 집합 ────────────────────────
    # pe-sieve 가 명시적으로 스캔하고 이상없음으로 판정한 프로세스.
    # ProcessWatcher 가 감지해 all_pids 에 포함됐더라도 악성 체인에 없는 한
    # 트리에 추가하지 않음 (화이트리스트와 동일하게 취급).
    pesieve_cleared_pids: set[int] = {
        r.pid
        for r in (getattr(result, "pe_sieve_results", None) or [])
        if not getattr(r, "error", False) and getattr(r, "suspicious", 0) == 0
    }

    # ── filtered_events에 이벤트가 있는 PID (WriteFile·TCP·RegSetValue 등) ──
    pids_with_events: set[int] = {
        ev.pid for ev in (getattr(result, "filtered_events", None) or [])
    }

    # ── 악성 실행 체인 루트 씨드 결정 ────────────────────────────────
    malware_chain: set[int] = set()

    if sample_pid is not None:
        # EXE 모드: 직접 실행 PID를 루트로 사용
        malware_chain.add(sample_pid)
    else:
        # ShellExecute 모드: 확장자 → 호스트 앱 PID 탐색
        cfg = getattr(result, "config", None)
        sp  = getattr(cfg, "sample_path", None)
        if sp is not None:
            ext        = getattr(sp, "suffix", "").lower()
            host_names = _SHELL_HOST_MAP.get(ext, frozenset())
            for p in all_procs:
                if p.name.lower() in host_names:
                    malware_chain.add(p.pid)

    # pe-sieve/HH 탐지 PID는 항상 포함
    malware_chain.update(suspicious_pids)

    # 폴백-1: 호스트 앱 미발견 → ProcMon 이벤트 있는 비WL 프로세스
    if not malware_chain:
        for p in all_procs:
            if p.pid in pids_with_events and p.name.lower() not in _WL:
                malware_chain.add(p.pid)

    # 폴백-2: ProcMon 미사용 등 완전 실패 → 비WL 전체
    if not malware_chain:
        for p in all_procs:
            if p.name.lower() not in _WL:
                malware_chain.add(p.pid)

    # 루트 씨드 자손 반복 확장 (WL 이름이더라도 체인 내 자식은 포함)
    changed = True
    while changed:
        changed = False
        for p in all_procs:
            if p.pid not in malware_chain and p.ppid in malware_chain:
                malware_chain.add(p.pid)
                changed = True

    # ── 전체 parent→children 맵 ──────────────────────────────────────
    children_map: dict[int, list] = {}
    for p in all_procs:
        children_map.setdefault(p.ppid, []).append(p)

    def _has_suspicious_desc(pid: int) -> bool:
        if pid in suspicious_pids:
            return True
        for child in children_map.get(pid, []):
            if _has_suspicious_desc(child.pid):
                return True
        return False

    display, excluded = [], 0
    for p in all_procs:
        # 분석 도구(HH, pe-sieve)는 탐지 결과와 무관하게 항상 제외
        if p.pid in _tool_pids:
            excluded += 1
            continue
        # 악성 체인 내부 / pe-sieve 의심 / sample_pid → 항상 표시
        if p.pid in malware_chain or p.pid in suspicious_pids or p.pid == sample_pid:
            display.append(p)
            continue
        # 의심 자손이 있으면 표시 (부모 경로 보존)
        if _has_suspicious_desc(p.pid):
            display.append(p)
            continue
        # 제외 조건: 아래 중 하나라도 해당하면 제외
        #   1. 화이트리스트 프로세스명
        #   2. ProcMon 이벤트 없음 (ReadFile 전용 백그라운드 등)
        #   3. pe-sieve 가 명시적으로 이상없음 판정한 프로세스
        if (p.name.lower() in _WL
                or p.pid not in pids_with_events
                or p.pid in pesieve_cleared_pids):
            excluded += 1
        else:
            # 체인 외부지만 ProcMon 이벤트 있고 pe-sieve 미스캔 비WL: 보여줌
            display.append(p)
    return display, excluded


def _process_tree_html(result) -> str:
    """신규 프로세스를 부모-자식 트리로 시각화합니다."""
    new_procs, _excl = _compute_display_procs(result)
    snapshot   = getattr(result, "proc_after_snapshot", {}) or {}
    sample_pid = getattr(result, "sample_pid", None)

    if not new_procs:
        return ""

    # ── 주석 맵 빌드 ────────────────────────────────────────────────
    # pe-sieve: 의심 있는 것만
    pe_map: dict[int, object] = {
        r.pid: r
        for r in (getattr(result, "pe_sieve_results", None) or [])
        if not r.error and r.suspicious > 0
    }
    # hollows-hunter: 의심 프로세스
    hh_map: dict[int, object] = {}
    hh_r = getattr(result, "hh_result", None)
    if hh_r and not getattr(hh_r, "error", None):
        for pr in getattr(hh_r, "process_results", []):
            if getattr(pr, "suspicious", 0) > 0:
                hh_map[pr.pid] = pr

    # 종료된 프로세스 PID
    term_pids = {p.pid for p in result.process_diff.get("terminated_processes", [])}

    new_pid_set = {p.pid for p in new_procs}

    # ── 부모→자식 매핑 (신규만) ──────────────────────────────────────
    children: dict[int, list] = {}
    for proc in new_procs:
        children.setdefault(proc.ppid, []).append(proc)

    # ── 루트 부모 PIDs (신규가 아닌 부모) ────────────────────────────
    root_parent_pids: set[int] = {
        p.ppid for p in new_procs if p.ppid not in new_pid_set
    }
    # pe-sieve/HH 탐지 기존 프로세스 (new_processes 에 없는 것):
    # 인젝션 후 자식 없이 C2 통신만 하는 경우에도 트리에 표시.
    # HH 탐지 중 쉘코드 전용(PE인젝션 없음)은 JIT 컴파일 오탐 가능성이 높아 제외.
    # (Chrome V8, DWM, SearchApp 등 JIT 엔진은 HH가 쉘코드로 오인함)
    _hh_pe_injected = {
        pid for pid, pr in hh_map.items()
        if getattr(pr, "implanted_pe", 0) > 0
    }
    # 트리에서 제외된 HH 쉘코드 전용 탐지 기존 프로세스 집합 (헤더 노트용)
    _hh_shc_only_excl = (set(hh_map) - _hh_pe_injected - new_pid_set - set(pe_map))
    root_parent_pids |= (set(pe_map) | _hh_pe_injected) - new_pid_set

    def get_snap(pid: int):
        if pid in snapshot:
            return snapshot[pid]
        for p in new_procs:
            if p.pid == pid:
                return p
        return None

    # ── 노드 렌더러 ─────────────────────────────────────────────────
    def render_node(pid: int, proc, is_new: bool, depth: int = 0) -> str:
        pe_r  = pe_map.get(pid)
        hh_r_ = hh_map.get(pid)
        is_suspicious = bool(pe_r or hh_r_)
        is_sample     = (pid == sample_pid)
        is_terminated = pid in term_pids
        node_children = children.get(pid, [])
        has_children  = bool(node_children)

        # 이름·경로·커맨드라인
        name = f"PID {pid}"
        exe  = ""
        cmd  = ""
        if proc:
            name = getattr(proc, "name", "") or name
            exe  = getattr(proc, "exe",  "") or ""
            cl   = getattr(proc, "cmdline", []) or []
            if len(cl) > 1:
                cmd = " ".join(cl[1:])[:160]

        # 노드 스타일
        if is_suspicious:
            name_cls = "pt-name-suspicious"
            icon = "🚨"
        elif is_sample:
            name_cls = "pt-name-sample"
            icon = "🎯"
        elif is_new:
            name_cls = "pt-name-new"
            icon = "⚡"
        else:
            name_cls = "pt-name-existing"
            icon = "💻"

        # 배지
        bdg = ""
        if is_new:
            bdg += _b("신규", "orange")
        if is_terminated:
            bdg += _b("종료됨", "gray")
        if pe_r:
            shc = getattr(pe_r, "implanted_shc", 0)
            pei = getattr(pe_r, "implanted_pe",  0)
            hk  = getattr(pe_r, "hooked",        0)
            if shc: bdg += _b(f"쉘코드 {shc}", "red")
            if pei: bdg += _b(f"PE인젝션 {pei}", "orange")
            if hk:  bdg += _b(f"훅 {hk}", "yellow")
        elif hh_r_:
            shc = getattr(hh_r_, "implanted_shc", 0)
            pei = getattr(hh_r_, "implanted_pe",  0)
            if shc: bdg += _b(f"HH 쉘코드 {shc}", "red")
            if pei: bdg += _b(f"HH PE인젝션 {pei}", "orange")

        # 토글 ID
        uid = f"ptc_{depth}_{pid}"
        if has_children:
            arr  = f"<span class='pt-arr' id='arr_{uid}'>▼</span>"
            rclick = f"class='pt-row pt-clickable' onclick=\"togglePT('{uid}')\""
        else:
            arr    = "<span class='pt-leaf'>◆</span>"
            rclick = "class='pt-row'"

        html  = "<div class='pt-wrap'>"
        html += (
            f"<div {rclick}>"
            f"{arr} {icon}&nbsp;"
            f"<span class='{name_cls}'>{_e(name)}</span>"
            f"<span class='pt-pid'>&nbsp;PID {pid}</span>"
            f"&nbsp;{bdg}"
            f"</div>"
        )
        if exe:
            html += f"<div class='pt-meta'>{_e(exe)}</div>"
        if cmd:
            html += f"<div class='pt-meta' style='color:#484f58'>▸ {_e(cmd)}</div>"

        if has_children:
            html += f"<div class='pt-children' id='{uid}'>"
            for child in sorted(node_children, key=lambda p: p.pid):
                html += render_node(child.pid, child, is_new=True, depth=depth + 1)
            html += "</div>"

        html += "</div>"
        return html

    # ── 전체 트리 렌더링 ─────────────────────────────────────────────
    _excl_note = (
        f"&nbsp;·&nbsp;<span style='color:#6e7681'>정상 시스템 프로세스 {_excl}개 제외</span>"
        if _excl else ""
    )
    _hh_excl_note = (
        f"&nbsp;·&nbsp;<span style='color:#6e7681' "
        f"title='JIT 컴파일 엔진(Chrome V8, DWM, SearchApp 등) HH 쉘코드 오탐 가능성'>"
        f"HH 쉘코드 전용 탐지 {len(_hh_shc_only_excl)}개 제외</span>"
        if _hh_shc_only_excl else ""
    )
    parts = [
        "<div style='display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;margin-bottom:.6rem'>",
        "<span style='font-size:.78rem;color:#8b949e'>",
        "💻 기존 프로세스&nbsp;&nbsp;",
        "⚡ <span style='color:#ffa657'>신규 프로세스</span>&nbsp;&nbsp;",
        "🎯 <span style='color:#e3b341'>샘플</span>&nbsp;&nbsp;",
        "🚨 <span style='color:#ff7b72'>의심 (pe-sieve/HH)</span>",
        _excl_note,
        _hh_excl_note,
        "</span>",
        "<button onclick='expandAllPT()' style='background:#21262d;border:1px solid #30363d;"
        "color:#8b949e;border-radius:4px;padding:.15rem .6rem;font-size:.73rem;cursor:pointer'>모두 펼치기</button>",
        "<button onclick='collapseAllPT()' style='background:#21262d;border:1px solid #30363d;"
        "color:#8b949e;border-radius:4px;padding:.15rem .6rem;font-size:.73rem;cursor:pointer'>모두 접기</button>",
        "</div>",
        "<div class='ptree'>",
    ]

    for ppid in sorted(root_parent_pids):
        if ppid == 0:
            # PID 0 자식들은 직접 루트로 표시
            for proc in sorted(children.get(0, []), key=lambda p: p.pid):
                parts.append(render_node(proc.pid, proc, is_new=True, depth=0))
        else:
            parent = get_snap(ppid)
            parts.append(render_node(ppid, parent, is_new=False, depth=0))

    parts.append("</div>")
    return "\n".join(parts)


def _process_html(result) -> str:
    all_new = result.process_diff.get("new_processes", [])
    if not all_new:
        return "<p class='alert alert-success'>신규 프로세스 없음</p>"

    new_procs, excl_count = _compute_display_procs(result)

    # ── 프로세스 트리 ────────────────────────────────────────────────
    tree_html = _process_tree_html(result)

    # ── 플랫 테이블 (악성 체인 필터) ────────────────────────────────
    excl_note = ""
    if excl_count:
        excl_note = (
            f"<p style='font-size:.78rem;color:#6e7681;margin:.3rem 0 .5rem'>"
            f"무관 프로세스 {excl_count}개 표시 제외 "
            f"(화이트리스트 시스템 프로세스 또는 ProcMon 활동 없는 프로세스, 의심 탐지 없음)</p>"
        )

    rows = ""
    for p in new_procs:
        cmdline = " ".join(p.cmdline) if p.cmdline else ""
        rows += (
            f"<tr>"
            f"<td class='mono'>{p.pid}</td>"
            f"<td class='mono ev-process'>{_e(p.name)}</td>"
            f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(p.exe or '')}</td>"
            f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(cmdline[:120])}</td>"
            f"</tr>"
        )
    table_html = (
        "<table id='tbl-process'><tr><th>PID</th><th>프로세스</th><th>경로</th><th>명령줄</th></tr>"
        f"{rows}</table>"
    )

    # ── 전체 프로세스 기록 (화이트리스트 오탐만 제외) ────────────────
    all_procs_html = _all_procs_html(result, chain_pids={p.pid for p in new_procs})

    return tree_html + excl_note + table_html + all_procs_html


def _all_procs_html(result, chain_pids: set) -> str:
    """화이트리스트 오탐만 제외한 신규 프로세스 전체 기록 테이블."""
    all_new = result.process_diff.get("new_processes", [])
    try:
        from analysis.shellcode_analyzer import _SYSTEM_PROC_WHITELIST as _WL
    except Exception:
        _WL = frozenset()

    table_procs = [p for p in all_new if p.name.lower() not in _WL]
    wl_excl = len(all_new) - len(table_procs)

    note = (
        f"<p style='font-size:.78rem;color:#6e7681;margin:1.2rem 0 .4rem'>"
        f"<strong style='color:#cdd9e5'>전체 프로세스 기록</strong>"
        f"&nbsp;— 오탐(화이트리스트) {wl_excl}개 제외 · {len(table_procs)}개"
        f"&nbsp;·&nbsp;<span style='opacity:.5'>흐린 행</span> = 악성 체인 외부</p>"
    )

    rows = ""
    for p in table_procs:
        cmdline = " ".join(p.cmdline) if p.cmdline else ""
        tr_open = "<tr>" if p.pid in chain_pids else "<tr style='opacity:.45'>"
        rows += (
            f"{tr_open}"
            f"<td class='mono'>{p.pid}</td>"
            f"<td class='mono ev-process'>{_e(p.name)}</td>"
            f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(p.exe or '')}</td>"
            f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(cmdline[:120])}</td>"
            f"</tr>"
        )

    return (
        note
        + "<table id='tbl-process-all'>"
        + "<tr><th>PID</th><th>프로세스</th><th>경로</th><th>명령줄</th></tr>"
        + rows
        + "</table>"
    )


def _render_proc_result(proc, exe: str = "") -> str:
    """PeSieveResult → HTML 블록 (헤더 + 모듈 테이블)

    Parameters
    ----------
    proc : PeSieveResult
    exe  : 프로세스 전체 경로 (psutil 스냅샷에서 보완, 없으면 빈 문자열)
    """
    arch      = "64bit" if proc.is_64bit else "32bit"
    shc_badge = _b(f"쉘코드 {proc.implanted_shc}개", "red") if proc.implanted_shc else ""
    pe_badge  = _b(f"PE 인젝션 {proc.implanted_pe}개", "orange") if proc.implanted_pe else ""
    proc_name = _e(proc.name) if getattr(proc, "name", "") else ""
    name_tag  = (
        f" <span style='color:#e3b341;font-weight:600'>{proc_name}</span>"
        if proc_name else ""
    )
    exe_tag = (
        f"<div style='font-size:0.72rem;color:#8b949e;margin:.1rem 0 .5rem 0'>"
        f"{_e(exe)}</div>"
        if exe else ""
    )

    if not proc.modules:
        return (
            f"<p style='margin:.4rem 0;font-size:0.85rem'>🚨 PID {proc.pid}"
            f"{name_tag} "
            f"<span style='color:#8b949e'>({_e(arch)})</span> "
            f"{_b(f'의심 {proc.suspicious}개', 'orange')} {shc_badge} {pe_badge}</p>"
            f"{exe_tag}"
        )
    rows = ""
    for mod in proc.modules:
        mod_name  = Path(mod.module_path).name if mod.module_path else "-"
        dump_name = Path(mod.dump_file).name   if mod.dump_file   else "-"
        if mod.is_shellcode:
            kind_badge = _b("쉘코드", "red")
        elif mod.implanted_count:
            kind_badge = _b("PE 인젝션", "orange")
        else:
            kind_badge = _b("훅/패치", "yellow")
        rows += (
            f"<tr>"
            f"<td class='mono' style='color:#c9d1d9'>{_e(mod_name)}</td>"
            f"<td>{kind_badge}</td>"
            f"<td class='mono' style='color:#8b949e'>{mod.patches_count}</td>"
            f"<td class='mono' style='color:#8b949e'>{mod.implanted_count}</td>"
            f"<td class='mono ev-file'>{_e(dump_name)}</td>"
            f"</tr>"
        )
    return (
        f"<h3>🚨 PID {proc.pid}{name_tag} "
        f"<span style='color:#8b949e;font-size:0.8rem;font-weight:normal'>"
        f"({_e(arch)}) &nbsp;"
        f"{_b(f'의심 {proc.suspicious}개', 'orange')} {shc_badge} {pe_badge}"
        f"</span></h3>"
        f"{exe_tag}"
        f"<table>"
        f"<tr><th>모듈</th><th>유형</th><th>패치 수</th><th>이식 수</th><th>덤프 파일</th></tr>"
        f"{rows}</table>"
    )


def _mem_is_noise(proc_result, wl: frozenset) -> bool:
    """화이트리스트 프로세스 + PE인젝션·교체 없음 → 시스템 프로세스 오탐으로 간주해 숨김."""
    name = (getattr(proc_result, "name", "") or "").lower()
    if name not in wl:
        return False
    pe       = getattr(proc_result, "implanted_pe", 0) or 0
    replaced = getattr(proc_result, "replaced",     0) or 0
    return pe == 0 and replaced == 0


def _shellcode_html(result) -> str:
    """pe-sieve / hollows-hunter 쉘코드·인젝션 결과"""
    hh_r    = getattr(result, "hh_result",        None)
    pe_list = getattr(result, "pe_sieve_results",  None) or []

    try:
        from analysis.shellcode_analyzer import _SYSTEM_PROC_WHITELIST as _MEM_WL
    except ImportError:
        _MEM_WL = frozenset()

    if hh_r is None and not pe_list:
        return (
            "<p class='alert alert-info'>"
            "pe-sieve / hollows-hunter 미설치 — 메모리 스캔 생략됨. "
            "<code>C:\\Tools</code> 또는 <code>PATH</code>에 실행 파일 배치 후 재분석하면 표시됩니다.</p>"
        )

    parts = []

    # ── hollows-hunter 집계 ────────────────────────────────────────
    hh_scanned = 0
    hh_susp    = 0
    hh_shc     = 0
    hh_pe_inj  = 0
    if hh_r is not None:
        if hh_r.error:
            full_err  = _e(hh_r.error)
            short_err = _e(hh_r.error[:200]) + ("…" if len(hh_r.error) > 200 else "")
            parts.append(
                f"<p style='color:#484f58;font-size:.78rem;margin:.3rem 0' title='{full_err}'>"
                f"hollows-hunter: {short_err}</p>"
            )
        else:
            hh_scanned = hh_r.total_scanned
            hh_susp    = len(hh_r.suspicious_processes)
            hh_shc     = sum(r.implanted_shc for r in hh_r.process_results)
            hh_pe_inj  = sum(r.implanted_pe  for r in hh_r.process_results)

    # ── pe-sieve 신규 프로세스 집계 ───────────────────────────────
    pe_valid   = [r for r in pe_list if not r.error]
    pe_errors  = [r for r in pe_list if r.error]
    pe_susp    = [r for r in pe_valid if r.suspicious > 0]
    pe_shc     = sum(r.implanted_shc for r in pe_valid)
    pe_pe_inj  = sum(r.implanted_pe  for r in pe_valid)

    has_hh_data = hh_r is not None and not hh_r.error
    has_pe_data = bool(pe_valid)

    # ── 요약 카드 ──────────────────────────────────────────────────
    if has_hh_data or has_pe_data:
        rows = ""
        if has_hh_data:
            ss = "#ff7b72" if hh_susp   else "#56d364"
            pi = "#e3b341" if hh_pe_inj else "#8b949e"
            sc = "#ff7b72" if hh_shc    else "#8b949e"
            rows += (
                f"<tr><td>hollows-hunter (전체 시스템)</td><td>"
                f"{hh_scanned}개 스캔 &nbsp;"
                f"<b style='color:{ss}'>의심 {hh_susp}개</b> &nbsp;"
                f"<b style='color:{pi}'>PE인젝션 {hh_pe_inj}개</b> &nbsp;"
                f"<b style='color:{sc}'>쉘코드 {hh_shc}개</b>"
                f"</td></tr>"
            )
        if has_pe_data:
            pss = "#ff7b72" if pe_susp   else "#56d364"
            ppi = "#e3b341" if pe_pe_inj else "#8b949e"
            psc = "#ff7b72" if pe_shc    else "#8b949e"
            rows += (
                f"<tr><td>pe-sieve (신규 + 의심 DLL 로드 프로세스)</td><td>"
                f"{len(pe_valid)}개 스캔 &nbsp;"
                f"<b style='color:{pss}'>의심 {len(pe_susp)}개</b> &nbsp;"
                f"<b style='color:{ppi}'>PE인젝션 {pe_pe_inj}개</b> &nbsp;"
                f"<b style='color:{psc}'>쉘코드 {pe_shc}개</b>"
                f"</td></tr>"
            )
        parts.append(
            f"<div class='card' style='margin-bottom:1rem'>"
            f"<table class='kv'>{rows}</table>"
            f"</div>"
        )

    # ── PID → ProcessSnapshot 교차 조회 (HH 포함, pe-sieve보다 앞에 정의)
    _snap_map_hh: dict[int, object] = {}
    for _snap in (result.process_diff or {}).get("new_processes", []):
        _snap_map_hh[_snap.pid] = _snap

    # ── hollows-hunter 상세 (의심 프로세스만, 화이트리스트 noise 제외) ────
    if has_hh_data:
        hh_show    = [p for p in hh_r.suspicious_processes if not _mem_is_noise(p, _MEM_WL)]
        hh_noise_n = len(hh_r.suspicious_processes) - len(hh_show)
        if hh_show:
            for proc in hh_show:
                snap_hh = _snap_map_hh.get(proc.pid)
                if snap_hh and not proc.name:
                    proc.name = getattr(snap_hh, "name", "") or ""
                snap_exe_hh = getattr(snap_hh, "exe", "") or "" if snap_hh else ""
                parts.append(_render_proc_result(proc, exe=snap_exe_hh))
            if hh_noise_n:
                parts.append(
                    f"<p style='font-size:.76rem;color:#6e7681;margin:.25rem 0'>"
                    f"시스템 프로세스 {hh_noise_n}개 제외 "
                    f"(쉘코드·훅만 탐지, PE인젝션·교체 없음 — 오탐 가능성 높음)</p>"
                )
        else:
            if hh_noise_n:
                parts.append(
                    f"<p class='alert alert-success'>✅ hollows-hunter: 유의미한 인젝션 미탐지"
                    f"<span style='font-size:.8rem;color:#6e7681'> "
                    f"(시스템 프로세스 {hh_noise_n}개 제외)</span></p>"
                )
            else:
                parts.append(
                    "<p class='alert alert-success'>✅ hollows-hunter: 인젝션 / 쉘코드 미탐지</p>"
                )

    # ── pe-sieve 프로세스 상세 ────────────────────────────────────
    if pe_list:
        parts.append(
            "<h3 style='margin-top:1.5rem;border-top:1px solid #30363d;padding-top:.75rem'>"
            "pe-sieve — 신규 프로세스 &amp; 의심 DLL 로드 프로세스 스캔 결과</h3>"
        )

        pe_noise_n = 0
        for r in pe_list:
            # pe-sieve JSON에는 name이 없으므로 psutil 스냅샷에서 보완
            snap = _snap_map_hh.get(r.pid)
            if snap and not r.name:
                r.name = getattr(snap, "name", "") or ""

            if r.error:
                full_err  = _e(r.error)
                short_err = _e(r.error[:160]) + ("…" if len(r.error) > 160 else "")
                name_hint = f" [{_e(r.name)}]" if r.name else ""
                parts.append(
                    f"<p style='color:#8b949e;font-size:0.82rem;margin:.25rem 0' title='{full_err}'>"
                    f"PID {r.pid}{name_hint}: {short_err}</p>"
                )
            elif r.suspicious > 0:
                if _mem_is_noise(r, _MEM_WL):
                    pe_noise_n += 1
                else:
                    snap_exe = getattr(snap, "exe", "") or "" if snap else ""
                    parts.append(_render_proc_result(r, exe=snap_exe))
            else:
                arch      = "64bit" if r.is_64bit else "32bit"
                name_part = (
                    f"&nbsp;<span class='mono' style='color:#e3b341'>{_e(r.name)}</span>"
                    if r.name else ""
                )
                exe_part = ""
                if snap:
                    exe_val = getattr(snap, "exe", "") or ""
                    if exe_val:
                        exe_part = (
                            f"&nbsp;<span style='color:#8b949e;font-size:0.72rem'>"
                            f"— {_e(exe_val)}</span>"
                        )
                parts.append(
                    f"<p style='color:#56d364;font-size:0.82rem;margin:.25rem 0'>"
                    f"✅ PID {r.pid}{name_part}"
                    f"&nbsp;<span style='color:#6e7681'>({_e(arch)})</span>"
                    f": 이상 없음{exe_part}</p>"
                )
        if pe_noise_n:
            parts.append(
                f"<p style='font-size:.76rem;color:#6e7681;margin:.25rem 0'>"
                f"pe-sieve: 시스템 프로세스 {pe_noise_n}개 제외 "
                f"(PE인젝션·교체 없음 — 오탐 가능성 높음)</p>"
            )

    # ── 쉘코드 덤프 재분석 결과 ───────────────────────────────────────
    analyses = getattr(result, "shellcode_analyses", None) or []
    if analyses:
        parts.append(
            "<h3 style='margin-top:1.5rem;border-top:1px solid #30363d;"
            "padding-top:.75rem'>🔬 쉘코드 덤프 재분석 (YARA + CAPA)</h3>"
        )
        hits      = [sa for sa in analyses if sa.has_findings]
        no_hits   = [sa for sa in analyses if not sa.has_findings and not sa.error]
        err_items = [sa for sa in analyses if sa.error and not sa.has_findings]

        hit_color = "#ff7b72" if hits else "#56d364"
        parts.append(
            f"<p style='color:#8b949e;font-size:.82rem;margin:.3rem 0 .75rem'>"
            f"분석 파일 {len(analyses)}개 &nbsp;·&nbsp; "
            f"<b style='color:{hit_color}'>시그니처 히트 {len(hits)}개</b>"
            + (f" &nbsp;·&nbsp; 이상 없음 {len(no_hits)}개" if no_hits else "")
            + (f" &nbsp;·&nbsp; <span style='color:#ff7b72'>오류 {len(err_items)}개</span>" if err_items else "")
            + f"</p>"
        )

        # ── 전체 스캔 파일 목록 테이블 ────────────────────────────────
        # hits → no_hits → err_items 순으로 출력
        rows = ""
        for sa in hits + no_hits + err_items:
            fname     = Path(sa.dump_file).name
            folder    = Path(sa.dump_file).parent.name   # e.g. "process_3812"
            size_str  = _fmt_bytes(sa.size_bytes) if sa.size_bytes else "?"

            # 프로세스 셀
            proc_cell = (
                f"<span class='ev-process mono' style='font-size:.8rem'>"
                f"{_e(sa.proc_name)}</span>"
                f"<span style='color:#8b949e;font-size:.75rem'> ({sa.pid})</span>"
            )

            # 결과 셀
            if sa.error and not sa.has_findings:
                result_cell = (
                    f"<span style='color:#ff7b72;font-size:.75rem'>"
                    f"오류: {_e(sa.error[:120])}</span>"
                )
            elif sa.has_findings:
                yara_badges = " ".join(_b(m, "red") for m in sa.yara_matches)
                capa_badges = " ".join(
                    "<span class='badge badge-purple' title='"
                    + _e((t.tactic or "") + " / " + (t.technique_name or ""))
                    + "'>" + _e(t.technique_id) + "</span>"
                    for t in sa.capa_techs
                )
                result_cell = (yara_badges + " " + capa_badges).strip()
            else:
                result_cell = "<span style='color:#56d364;font-size:.8rem'>이상없음</span>"

            # 해시 (있으면 details 토글)
            hash_detail = ""
            if sa.md5 or sa.sha256:
                hash_inner = ""
                if sa.md5:
                    hash_inner += (
                        f"<tr><td style='color:#8b949e;font-size:.7rem;"
                        f"padding-right:.5rem;white-space:nowrap'>MD5</td>"
                        f"<td class='mono' style='font-size:.7rem;word-break:break-all;"
                        f"color:#adbac7'>{_e(sa.md5)}</td></tr>"
                    )
                if sa.sha256:
                    hash_inner += (
                        f"<tr><td style='color:#8b949e;font-size:.7rem;"
                        f"padding-right:.5rem;white-space:nowrap'>SHA256</td>"
                        f"<td class='mono' style='font-size:.7rem;word-break:break-all;"
                        f"color:#adbac7'>{_e(sa.sha256)}</td></tr>"
                    )
                hash_detail = (
                    f"<details style='margin-top:.2rem'>"
                    f"<summary style='color:#484f58;font-size:.7rem;cursor:pointer'>"
                    f"해시</summary>"
                    f"<table style='border-collapse:collapse;margin-top:.2rem'>"
                    f"{hash_inner}</table></details>"
                )

            row_style = (
                "background:rgba(255,123,114,.06)"
                if sa.has_findings
                else ("background:rgba(255,123,114,.03)" if sa.error else "")
            )
            rows += (
                f"<tr style='{row_style}'>"
                # 파일명 + 폴더명 + 전체 경로 토글
                f"<td class='mono' style='font-size:.8rem'>"
                f"<div style='color:#6e7681;font-size:.72rem;margin-bottom:.1rem'>"
                f"📁 {_e(folder)}</div>"
                f"<details><summary style='cursor:pointer;list-style:none'>"
                f"{_e(fname)}</summary>"
                f"<span style='color:#8b949e;font-size:.7rem;word-break:break-all'>"
                f"{_e(sa.dump_file)}</span></details>"
                f"{hash_detail}</td>"
                # 프로세스
                f"<td>{proc_cell}</td>"
                # 크기
                f"<td class='mono' style='color:#8b949e;text-align:right;font-size:.8rem'>"
                f"{size_str}</td>"
                # 결과
                f"<td>{result_cell}</td>"
                f"</tr>"
            )

        parts.append(
            "<table id='tbl-shc-files' style='width:100%'>"
            "<tr><th>파일명</th><th>프로세스</th><th>크기</th><th>결과 (YARA / CAPA)</th></tr>"
            f"{rows}</table>"
        )

    return "\n".join(parts)


def _ioc_html(result) -> str:
    ioc  = result.ioc_report
    pcap = result.pcap_result
    if not ioc:
        return ""
    parts = []

    _IOC_LIMIT = 1000

    # ── IP→도메인 종합 매핑 (DNS 응답 + TLS SNI) ──────────────────
    combined_dom: dict[str, list[str]] = {}
    if pcap:
        for ip, doms in (pcap.ip_to_domain or {}).items():
            lst = combined_dom.setdefault(ip, [])
            for d in doms:
                if d not in lst:
                    lst.append(d)
        for t in getattr(pcap, "tls_info", []):
            if t.dst_ip and t.sni:
                lst = combined_dom.setdefault(t.dst_ip, [])
                if t.sni not in lst:
                    lst.append(t.sni)

    # ── IP→포트 집계 (pcap 연결 목록) ────────────────────────────
    ip_ports: dict[str, list[str]] = {}
    if pcap:
        for c in getattr(pcap, "connections", []):
            if _is_private_ip_str(c.dst_ip):
                continue
            entry = ip_ports.setdefault(c.dst_ip, [])
            label = f"{c.dst_port}/{c.proto.upper()}"
            if label not in entry:
                entry.append(label)

    # ── 외부 IP 테이블 (풍부한 컬럼) ─────────────────────────────
    if ioc.ip_addresses:
        pub_ips = ioc.ip_addresses[:_IOC_LIMIT]
        rows = ""
        for ip in pub_ips:
            doms  = combined_dom.get(ip, [])
            ports = sorted(ip_ports.get(ip, []),
                           key=lambda x: int(x.split("/")[0]) if x.split("/")[0].isdigit() else 0)
            dom_html = (
                "<span class='mono ev-network' style='font-size:.78rem'>"
                + _e(doms[0]) + "</span>"
                + (f"<span style='color:#8b949e'>&nbsp;+{len(doms)-1}</span>" if len(doms) > 1 else "")
                if doms else "<span style='color:#484f58'>-</span>"
            )
            port_html = (
                "&nbsp;".join(
                    f"<span style='background:#21262d;border-radius:4px;padding:.1rem .4rem;"
                    f"font-size:.72rem;font-family:monospace'>{_e(p)}</span>"
                    for p in ports[:5]
                ) + (f"<span style='color:#8b949e'>&nbsp;+{len(ports)-5}</span>" if len(ports) > 5 else "")
                if ports else "<span style='color:#484f58'>-</span>"
            )
            rows += (
                f"<tr>"
                f"<td class='mono ev-network'>{_e(ip)}</td>"
                f"<td>{dom_html}</td>"
                f"<td style='white-space:nowrap'>{port_html}</td>"
                f"<td data-geo-ip='{_e(ip)}' style='color:#8b949e;font-size:.78rem'>"
                f"<span style='color:#484f58'>…</span></td>"
                f"</tr>"
            )
        geo_ips_js = _json.dumps(pub_ips[:100])
        parts.append(
            "<h3>외부 IP</h3>"
            + _trunc_notice(len(ioc.ip_addresses), _IOC_LIMIT)
            + "<table id='tbl-ioc-ip'>"
            + "<tr><th>IP 주소</th><th>연관 도메인</th><th>포트</th><th>국가 / 기관</th></tr>"
            + rows + "</table>"
            + f"""<script>
(function(){{
  var ips={geo_ips_js};
  if(!ips.length) return;
  var cells={{}};
  document.querySelectorAll('[data-geo-ip]').forEach(function(el){{
    cells[el.getAttribute('data-geo-ip')]=el;
  }});
  function flag(cc){{
    if(!cc||cc.length!==2) return '';
    try{{return String.fromCodePoint(...[...cc.toUpperCase()].map(function(c){{return 0x1F1E0+c.charCodeAt(0)-65;}}));}}
    catch(e){{return '';}}
  }}
  var batches=[];
  for(var i=0;i<ips.length;i+=100) batches.push(ips.slice(i,i+100));
  Promise.all(batches.map(function(batch){{
    return fetch('http://ip-api.com/batch?fields=status,country,countryCode,org,as,query',{{
      method:'POST',
      headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify(batch.map(function(ip){{return {{query:ip}}; }}))
    }}).then(function(r){{return r.ok?r.json():[];}}).catch(function(){{return [];}});
  }})).then(function(results){{
    (results||[]).flat().forEach(function(item){{
      if(!item||item.status!=='success') return;
      var cell=cells[item.query];
      if(!cell) return;
      var f=flag(item.countryCode);
      var asn=(item.as||'').split(' ')[0];
      var org=(item.org||item.as||'').replace(/^AS\\d+\\s*/,'').split(' ').slice(0,4).join(' ');
      cell.innerHTML=(f?f+' ':'')+_e2(item.country||'-')
        +'<br><span style="color:#8b949e;font-size:.7rem">'+_e2(asn)
        +(org?' · '+_e2(org):'')+'</span>';
    }});
  }});
  function _e2(s){{return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}}
}})();
</script>"""
        )

    # ── 프로세스 매핑 조회 테이블 구성 ───────────────────────────
    # 도메인 → IP 역매핑 (URL 프로세스 매핑용)
    hostname_to_ips: dict[str, list[str]] = {}
    for _ip, _doms in combined_dom.items():
        for _d in _doms:
            hostname_to_ips.setdefault(_d.lower(), []).append(_ip)

    # (proto, dst_ip, dst_port) → 프로세스 목록  &  ip → 프로세스 목록
    pnmap = getattr(result, "process_network_map", [])
    _proc_lookup: dict[tuple, list[str]] = {}
    ip_proc_lookup: dict[str, list[str]] = {}
    for _pn in pnmap:
        _label = f"{_pn.process} ({_pn.pid})"
        _key   = (_pn.proto.upper(), _pn.remote_ip, _pn.remote_port)
        _proc_lookup.setdefault(_key, [])
        if _label not in _proc_lookup[_key]:
            _proc_lookup[_key].append(_label)
        _ipl = ip_proc_lookup.setdefault(_pn.remote_ip, [])
        if _label not in _ipl:
            _ipl.append(_label)
        for _mip in hostname_to_ips.get(_pn.remote_ip.lower(), []):
            _mk = (_pn.proto.upper(), _mip, _pn.remote_port)
            _proc_lookup.setdefault(_mk, [])
            if _label not in _proc_lookup[_mk]:
                _proc_lookup[_mk].append(_label)
            _mipl = ip_proc_lookup.setdefault(_mip, [])
            if _label not in _mipl:
                _mipl.append(_label)

    # WriteFile 이벤트 → 파일경로(소문자): 프로세스 매핑
    file_proc_map: dict[str, list[str]] = {}
    try:
        from parsers.procmon_csv import EventCategory as _EC
        for _ev in getattr(result, "filtered_events", []):
            if _ev.category != _EC.FILE or _ev.operation != "WriteFile":
                continue
            _lp    = _ev.path.lower()
            _label = f"{_ev.process} ({_ev.pid})"
            _lst   = file_proc_map.setdefault(_lp, [])
            if _label not in _lst:
                _lst.append(_label)
    except Exception:
        pass

    # HTTP 요청 → URL: 프로세스 매핑
    url_proc_map: dict[str, list[str]] = {}
    if pcap:
        for _r in getattr(pcap, "http_requests", []):
            _url = f"http://{_r.host}{_r.path or '/'}"
            _url_procs: list[str] = []
            for _hip in hostname_to_ips.get(_r.host.lower(), []):
                for _p in ip_proc_lookup.get(_hip, []):
                    if _p not in _url_procs:
                        _url_procs.append(_p)
            if _url_procs:
                url_proc_map[_url] = _url_procs

    # ── 나머지 IOC 목록 ───────────────────────────────────────────
    def _list_table(title: str, items: list, label: str, table_id: str = "") -> str:
        if not items:
            return ""
        id_attr = f" id='{table_id}'" if table_id else ""
        rows = "".join(f"<tr><td class='mono'>{_e(str(i))}</td></tr>" for i in items[:_IOC_LIMIT])
        return (
            f"<h3>{title}</h3>"
            + _trunc_notice(len(items), _IOC_LIMIT)
            + f"<table{id_attr}><tr><th>{label}</th></tr>{rows}</table>"
        )

    parts.append(_list_table("도메인", ioc.domains, "도메인", "tbl-ioc-domain"))

    # ── 드롭된 파일 (프로세스 매핑 포함) ──────────────────────────
    if ioc.dropped_files:
        rows = ""
        for fp in ioc.dropped_files[:_IOC_LIMIT]:
            procs = file_proc_map.get(fp.lower(), [])
            rows += (
                f"<tr>"
                f"<td class='mono'>{_e(fp)}</td>"
                + _proc_cell(procs) +
                f"</tr>"
            )
        parts.append(
            "<h3>드롭된 파일</h3>"
            + _trunc_notice(len(ioc.dropped_files), _IOC_LIMIT)
            + "<table id='tbl-ioc-file'>"
            + "<tr><th>파일 경로</th><th>프로세스</th></tr>"
            + rows + "</table>"
        )

    parts.append(_list_table("레지스트리 키", ioc.registry_keys, "키 경로", "tbl-ioc-reg"))

    # ── URL (프로세스 매핑 포함) ───────────────────────────────────
    if ioc.urls:
        rows = ""
        for url in ioc.urls[:_IOC_LIMIT]:
            procs = url_proc_map.get(url, [])
            rows += (
                f"<tr>"
                f"<td class='mono ev-network'>{_e(url)}</td>"
                + _proc_cell(procs) +
                f"</tr>"
            )
        parts.append(
            "<h3>URL</h3>"
            + _trunc_notice(len(ioc.urls), _IOC_LIMIT)
            + "<table id='tbl-ioc-url'>"
            + "<tr><th>URL</th><th>프로세스</th></tr>"
            + rows + "</table>"
        )

    return "\n".join(p for p in parts if p)


def _hunt_html(sample_sha256: str, ioc) -> str:
    """Hunt 탭 — abuse.ch 실시간 조회 UI"""
    chips: list[str] = []

    # 샘플 SHA256 칩
    if sample_sha256:
        short = sample_sha256[:20] + "…"
        chips.append(
            f"<span class='hunt-qchip hash' title='{_e(sample_sha256)}' "
            f"onclick=\"huntQuick('{_e(sample_sha256)}')\">🔑 {_e(short)}</span>"
        )

    # IOC IP 칩 (최대 8개)
    for ip in (ioc.ip_addresses[:8] if ioc else []):
        chips.append(
            f"<span class='hunt-qchip ip' onclick=\"huntQuick('{_e(ip)}')\">🌐 {_e(ip)}</span>"
        )

    # IOC 도메인 칩 (최대 6개)
    for d in (ioc.domains[:6] if ioc else []):
        chips.append(
            f"<span class='hunt-qchip domain' onclick=\"huntQuick('{_e(d)}')\">🔗 {_e(d)}</span>"
        )

    quick_html = ""
    if chips:
        quick_html = (
            "<div class='hunt-quick'>"
            "<span class='hunt-qlabel'>이번 분석 IOC →</span>"
            + "".join(chips)
            + "</div>"
        )

    return f"""
<h2>🕵️ Threat Hunt — abuse.ch</h2>

<div class="alert alert-info" style="font-size:.82rem;margin-bottom:.6rem">
  <strong>MalwareBazaar · ThreatFox · URLhaus · Feodo Tracker</strong>
  를 브라우저에서 직접 조회합니다.
  인터넷 연결이 필요하며, 격리 VM에서는 네트워크 정책을 확인하세요.
</div>

<div id="hunt-cors-warn" class="alert alert-warning"
     style="display:none;font-size:.82rem;margin-bottom:.8rem">
  ⚠ <strong>file:// 프로토콜 감지 — API 요청이 차단될 수 있습니다.</strong><br>
  브라우저는 <code>file://</code>에서 열린 페이지의 외부 fetch 를 CORS origin=null 로 처리합니다.<br>
  <strong>해결:</strong> <code>config.json</code> → <code>hunt.serve_port</code> 값을 설정하면 다음 실행부터
  <code>http://127.0.0.1:PORT</code>로 자동 서빙됩니다.
  현재 기본값: <code>18080</code> (이미 설정되어 있으면 리포트를 다시 생성하세요).
</div>
<script>
(function(){{
    if (window.location.protocol === 'file:') {{
        var w = document.getElementById('hunt-cors-warn');
        if (w) w.style.display = 'block';
    }}
}})();
</script>

<!-- 검색 박스 -->
<div class="hunt-box">
  <div class="hunt-row">
    <input id="hunt-q" class="hunt-input" type="text"
           placeholder="SHA256 · MD5 · IP 주소 · 도메인 · URL …"
           oninput="huntInputChanged()"
           onkeydown="if(event.key==='Enter')huntSearch()">
    <button id="hunt-go" class="hunt-btn" onclick="huntSearch()">🔍 Hunt</button>
  </div>
  <div id="hunt-hint" class="hunt-hint"></div>
  {quick_html}
</div>

<!-- 서비스 상태 배지 -->
<div class="hunt-svcs">
  <span id="svc-mb"    class="svc-badge idle">📦 MalwareBazaar</span>
  <span id="svc-tf"    class="svc-badge idle">🎯 ThreatFox</span>
  <span id="svc-uh"    class="svc-badge idle">🌐 URLhaus</span>
  <span id="svc-feodo" class="svc-badge idle">👾 Feodo Tracker</span>
</div>

<!-- 결과 영역 -->
<div id="hunt-results"></div>
"""


def _build_hunt_cfg_js() -> str:
    """config.json 의 hunt 설정을 JS window.HUNT_CFG 객체 문자열로 반환합니다."""
    import json as _json
    try:
        from core.config_loader import get_hunt_cfg
        hunt = get_hunt_cfg()
    except Exception:
        # config_loader 로드 실패 시 하드코딩 기본값
        hunt = {
            "serve_port": 18080,
            "services": {
                "mb":     {"enabled": True,  "label": "MalwareBazaar",   "url": "https://mb-api.abuse.ch/api/v1/"},
                "tf":     {"enabled": True,  "label": "ThreatFox",       "url": "https://threatfox-api.abuse.ch/api/v1/"},
                "uh_url": {"enabled": True,  "label": "URLhaus (URL)",   "url": "https://urlhaus-api.abuse.ch/v1/url/"},
                "uh_host":{"enabled": True,  "label": "URLhaus (Host)",  "url": "https://urlhaus-api.abuse.ch/v1/host/"},
                "feodo":  {"enabled": True,  "label": "Feodo Tracker",   "url": "https://feodotracker.abuse.ch/api/v1/host_info/"},
            },
        }
    # relay_port: JS 가 릴레이 사용 여부를 판단하는 데 사용
    relay_port = hunt.get("serve_port", 0)
    js_obj = {
        "relay_port": relay_port if relay_port and relay_port > 0 else None,
        "services":   hunt.get("services", {}),
    }
    return _json.dumps(js_obj, ensure_ascii=False)


def generate_html_report(result, output_path: str) -> None:
    """AnalysisResult → HTML 파일 저장"""
    generated   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sample_name = result.config.sample_path.name if result.config.sample_path else "전체 시스템 모니터링"
    techs = result.behavior_report.techniques if result.behavior_report else []
    ioc   = result.ioc_report

    # ── 요약 카운트 ──────────────────────────────────────────────
    _hh      = getattr(result, "hh_result",        None)
    _ps_list = getattr(result, "pe_sieve_results",  None) or []

    # 의심 프로세스 수 집계 — shellcode_analyzer 와 동일한 오탐 필터 적용
    # (화이트리스트 시스템 프로세스 + 점수 미달 JIT 쉘코드 제외)
    try:
        from analysis.shellcode_analyzer import (
            suspicion_score  as _shc_score,
            _SYSTEM_PROC_WHITELIST as _SHC_WL,
            _SCORE_THRESHOLD as _SHC_THR,
        )
        _shc_filter_ok = True
    except Exception:
        _shc_filter_ok = False

    _new_pids_for_shc = {p.pid for p in result.process_diff.get("new_processes", [])}

    def _is_real_suspicious(r) -> bool:
        if not _shc_filter_ok:
            return True
        if getattr(r, "name", "").lower() in _SHC_WL:
            return False
        return r.pid in _new_pids_for_shc or _shc_score(r) >= _SHC_THR

    shc_total       = 0
    shc_fp_excluded = 0   # 오탐 필터로 제외된 수

    if _hh and not _hh.error:
        for _proc in _hh.suspicious_processes:
            if _is_real_suspicious(_proc):
                shc_total += 1
            else:
                shc_fp_excluded += 1

    for _r in _ps_list:
        if not _r.error and _r.suspicious > 0:
            if _is_real_suspicious(_r):
                shc_total += 1
            else:
                shc_fp_excluded += 1

    tech_count = len(techs)
    ip_count   = len(ioc.ip_addresses)  if ioc else 0
    file_count = len(ioc.dropped_files) if ioc else 0
    reg_added  = len(result.registry_diff.get("added",    []))
    reg_mod    = len(result.registry_diff.get("modified", []))
    # ProcMon 레지스트리 이벤트 수 (Regshot diff 와 독립적으로 집계)
    try:
        from parsers.procmon_csv import EventCategory as _EC
        _REG_OPS = {"RegSetValue", "RegCreateKey", "RegDeleteValue", "RegDeleteKey"}
        procmon_reg_count = sum(
            1 for e in result.filtered_events
            if e.category == _EC.REGISTRY and e.operation in _REG_OPS
        )
    except Exception:
        procmon_reg_count = 0

    # 파일시스템 탭 배지: ioc.dropped_files 가 아닌 실제 ProcMon 파일 이벤트 수
    try:
        from parsers.procmon_csv import EventCategory as _EC
        file_ev_count = sum(
            1 for e in result.filtered_events
            if e.category == _EC.FILE and e.operation in _FILE_OPS
        )
    except Exception:
        file_ev_count = 0
    conn_count = len(result.pcap_result.connections)  if result.pcap_result else 0
    dns_count  = len(result.pcap_result.dns_queries)  if result.pcap_result else 0
    ioc_total  = (ip_count + (len(ioc.domains) if ioc else 0)
                  + file_count + (len(ioc.registry_keys) if ioc else 0)
                  + (len(ioc.urls) if ioc else 0))

    # ── 위협 수준 ────────────────────────────────────────────────
    threat_score = tech_count + (1 if shc_total else 0)
    threat_color = "red" if threat_score >= 3 else ("orange" if threat_score >= 1 else "green")
    threat_label = "HIGH" if threat_score >= 3 else ("MEDIUM" if threat_score >= 1 else "CLEAN")

    tools_html = "  ".join(
        f"{_b('✔ ' + k, 'green') if v else _b('✘ ' + k, 'gray')}"
        for k, v in result.tools_used.items()
    )

    # ── 샘플 SHA256 (Hunt 탭 빠른 조회용) ───────────────────────────
    sample_sha256 = ""
    if result.config.sample_path:
        try:
            sample_sha256 = hashlib.sha256(
                Path(result.config.sample_path).read_bytes()
            ).hexdigest()
        except Exception:
            pass

    # ── 탭 배지 ──────────────────────────────────────────────────
    proc_count = len(_compute_display_procs(result)[0])
    tab1_b    = ""   # 기본 분석: 개요만 (배지 없음)
    tab_att_b = _tb(tech_count,  "red"    if tech_count  else "gray") if tech_count  else ""
    tab_proc_b= _tb(proc_count,  "orange" if proc_count  else "gray") if proc_count  else ""
    tab2_b    = _tb(file_ev_count, "blue" if file_ev_count else "gray") if file_ev_count else ""
    tab3_b    = _tb(reg_added + reg_mod,
                    "yellow" if (reg_added + reg_mod) else "gray") if (reg_added + reg_mod) else ""
    tab4_b    = _tb(conn_count,  "green"  if conn_count  else "gray") if conn_count  else ""
    tab_mem_b = _tb(shc_total,  "red"    if shc_total   else "gray") if shc_total   else ""
    tab5_b    = _tb(ioc_total,  "orange" if ioc_total   else "gray") if ioc_total   else ""

    _hunt_cfg_js = _build_hunt_cfg_js()
    body = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dynamic Analysis — {_e(sample_name)}</title>
<style>{_CSS}</style>
<script>window.HUNT_CFG = {_hunt_cfg_js};</script>
<script>{_JS}</script>
</head>
<body>
<div class="container">

<h1>🧪 Dynamic Malware Analysis Report</h1>
<p class="subtitle">
  샘플: <code>{_e(str(result.config.sample_path) if result.config.sample_path else "전체 시스템 모니터링")}</code> &nbsp;|&nbsp;
  생성: {generated} &nbsp;|&nbsp;
  모니터링: {result.config.timeout}초 &nbsp;|&nbsp;
  총 소요: {result.end_time - result.start_time:.1f}초
</p>
<p style="margin-bottom:1rem">
  {_b('위협 수준: ' + threat_label, threat_color)}
  &nbsp;
  {_b(f'MITRE {tech_count}건', 'red' if tech_count else 'gray')}
  {_b(f'인젝션·쉘코드 {shc_total}건' + (f' (오탐 {shc_fp_excluded}개 제외)' if shc_fp_excluded else ''), 'red' if shc_total else 'gray')}
  {_b(f'외부 IP {ip_count}건', 'orange' if ip_count else 'gray')}
  {_b(f'드롭 파일 {file_count}건', 'orange' if file_count else 'gray')}
</p>
<p style="margin-bottom:1.5rem">{tools_html}</p>

{"".join(f'<p class="alert alert-warning">⚠ {_e(e)}</p>' for e in result.errors) if result.errors else ""}

<!-- ── 탭 네비게이션 ── -->
<div class="tabs">
  <button class="tab-btn active" data-tab="tab-basic">
    📋 기본 분석{tab1_b}
  </button>
  <button class="tab-btn" data-tab="tab-attack">
    🎯 ATT&amp;CK{tab_att_b}
  </button>
  <button class="tab-btn" data-tab="tab-process">
    ⚙️ 프로세스{tab_proc_b}
  </button>
  <button class="tab-btn" data-tab="tab-filesystem">
    📂 파일시스템{tab2_b}
  </button>
  <button class="tab-btn" data-tab="tab-registry">
    🔑 레지스트리{tab3_b}
  </button>
  <button class="tab-btn" data-tab="tab-network">
    🌐 네트워크{tab4_b}
  </button>
  <button class="tab-btn" data-tab="tab-memory">
    🧠 메모리{tab_mem_b}
  </button>
  <button class="tab-btn" data-tab="tab-ioc">
    🔍 IOC{tab5_b}
  </button>
  <button class="tab-btn" data-tab="tab-hunt">
    🕵️ Hunt
  </button>
</div>

<!-- ══════════ 탭 1: 기본 분석 ══════════ -->
<div id="tab-basic" class="tab-panel active">

  <h2>📋 분석 개요</h2>
  <div class="grid2">
    <div class="card">
      <table class="kv">
        <tr><td>샘플 이름</td><td class="mono">{_e(sample_name)}</td></tr>
        <tr><td>샘플 PID</td><td class="mono">{result.sample_pid or '-'}</td></tr>
        <tr><td>추적 PID</td><td class="mono">{', '.join(str(p) for p in sorted(result.all_pids)) or '-'}</td></tr>
        <tr><td>전체 이벤트</td><td>{len(result.procmon_events):,}</td></tr>
        <tr><td>필터 후 이벤트</td><td>{len(result.filtered_events):,}</td></tr>
      </table>
    </div>
    <div class="card">
      <table class="kv">
        <tr><td>신규 프로세스</td><td>{proc_count}</td></tr>
        <tr><td>레지스트리 추가</td><td>{reg_added}</td></tr>
        <tr><td>레지스트리 변경</td><td>{reg_mod} <span style='color:#8b949e;font-size:.78rem'>(Regshot) / {procmon_reg_count:,} (ProcMon)</span></td></tr>
        <tr><td>네트워크 연결</td><td>{conn_count}</td></tr>
        <tr><td>DNS 쿼리</td><td>{dns_count}</td></tr>
        <tr><td>인젝션·쉘코드 의심</td><td><b style="color:{'#ff7b72' if shc_total else '#56d364'}">{shc_total}개 프로세스</b>{"<span style='color:#8b949e;font-size:.78rem'>&nbsp;(오탐 " + str(shc_fp_excluded) + "개 제외)</span>" if shc_fp_excluded else ""}</td></tr>
      </table>
    </div>
  </div>

</div>

<!-- ══════════ 탭 2: ATT&CK ══════════ -->
<div id="tab-attack" class="tab-panel">

  <h2>🎯 MITRE ATT&amp;CK 매핑</h2>
  {_section_html(result)}

</div>

<!-- ══════════ 탭 3: 프로세스 ══════════ -->
<div id="tab-process" class="tab-panel">

  <h2>⚙️ 프로세스 트리</h2>
  {_process_html(result)}

</div>

<!-- ══════════ 탭 4: 파일시스템 활동 ══════════ -->
<div id="tab-filesystem" class="tab-panel">

  <h2>📂 파일 시스템 활동 (ProcMon)</h2>
  {_file_events_html(result)[0]}

</div>

<!-- ══════════ 탭 3: 레지스트리 활동 ══════════ -->
<div id="tab-registry" class="tab-panel">

  <h2>🔑 레지스트리 변경 (ProcMon + Regshot)</h2>
  {_registry_events_html(result)}

</div>

<!-- ══════════ 탭 4: 네트워크 연결 ══════════ -->
<div id="tab-network" class="tab-panel">

  <h2>🌐 네트워크 활동 (tshark)</h2>
  {_network_html(result)}

</div>

<!-- ══════════ 탭 5: 메모리 ══════════ -->
<div id="tab-memory" class="tab-panel">

  <h2>🧠 메모리 인젝션 / 쉘코드 탐지</h2>
  {_shellcode_html(result)}

</div>

<!-- ══════════ 탭 6: IOC ══════════ -->
<div id="tab-ioc" class="tab-panel">

  <h2>💀 IOC 목록</h2>
  {_ioc_html(result)}

</div>

<!-- ══════════ 탭 7: Hunt ══════════ -->
<div id="tab-hunt" class="tab-panel">
  {_hunt_html(sample_sha256, ioc)}
</div>

</div>
{_PG_INIT}
</body>
</html>"""

    Path(output_path).write_text(body, encoding="utf-8")
