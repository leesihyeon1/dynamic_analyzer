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
    'tbl-mitre','tbl-process','tbl-process-all',
    'tbl-file',
    'tbl-reg-diff','tbl-reg-procmon',
    'tbl-net-beacon','tbl-net-tls','tbl-net-conn',
    'tbl-net-dga','tbl-net-dns','tbl-net-http',
    'tbl-net-smtp','tbl-net-ftp',
    'tbl-net-dec',
    'tbl-fn-dns','tbl-fn-http','tbl-fn-tcp',
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
    rows = []
    for t in techs:
        color = _TACTIC_COLOR.get(t.tactic, "gray")
        ref   = t.reference or f"https://attack.mitre.org/techniques/{t.technique_id.replace('.','/')}/"
        evidence_html = "".join(
            f"<div class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(ev[:120])}</div>"
            for ev in t.evidence[:5]
        )
        # sources 필드는 구버전 JSON 호환을 위해 getattr 사용
        src_badges = _source_badges(getattr(t, "sources", []) or [])
        rows.append(
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
        + "".join(rows) + "</table>"
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

    # ── 중복 제거: (pid, operation, path) 기준으로 그룹화 ────────────
    from collections import OrderedDict
    deduped: OrderedDict = OrderedDict()
    for e in events:
        key = (e.pid, e.operation, e.path)
        if key in deduped:
            deduped[key]["count"] += 1
        else:
            deduped[key] = {"event": e, "count": 1}
    deduped_events = list(deduped.values())
    total_deduped = len(deduped_events)

    rows = []
    op_color = {
        "WriteFile": "blue", "DeleteFile": "red",
        "RenameFile": "yellow", "SetEndOfFile": "gray", "CreateFile": "purple",
    }
    for item in deduped_events[:_FILE_LIMIT]:
        e     = item["event"]
        count = item["count"]
        count_html = (
            f"&nbsp;<span style='background:#30363d;color:#8b949e;font-size:0.68rem;"
            f"padding:1px 5px;border-radius:9px'>×{count}</span>"
            if count > 1 else ""
        )
        detail_str = (e.detail or "").strip()[:160]
        detail_html = (
            f"<div style='color:#6e7681;font-size:0.68rem;margin-top:.15rem'>{_e(detail_str)}</div>"
            if detail_str else ""
        )
        rows.append(
            f"<tr>"
            f"<td class='mono' style='color:#8b949e;white-space:nowrap'>{_e(e.time_str[:12])}</td>"
            f"<td class='mono'>{_e(e.process)} <span style='color:#8b949e'>({e.pid})</span></td>"
            f"<td>{_b(e.operation, op_color.get(e.operation,'gray'))}{count_html}</td>"
            f"<td class='mono ev-file'>{_e(e.path[:120])}{detail_html}</td>"
            f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(e.result)}</td>"
            f"</tr>"
        )
    dedup_note = (
        f"<p style='font-size:.78rem;color:#6e7681;margin:.2rem 0 .4rem'>"
        f"총 {total}건 → 중복 제거 후 {total_deduped}건 표시"
        f"&nbsp;·&nbsp;배지 <span style='background:#30363d;color:#8b949e;font-size:0.68rem;"
        f"padding:1px 5px;border-radius:9px'>×N</span> = 동일 이벤트 반복 횟수</p>"
        if total != total_deduped else ""
    )
    html = (
        _trunc_notice(total, _FILE_LIMIT)
        + dedup_note
        + "<table id='tbl-file'><tr><th>시각</th><th>프로세스</th><th>작업</th><th>경로</th><th>결과</th></tr>"
        + "".join(rows) + "</table>"
    )
    return html, total


def _reg_parse_detail(detail: str) -> str:
    """ProcMon RegSetValue detail 에서 '[TYPE] DATA' 문자열 추출."""
    import re
    m_type = re.search(r'\bType:\s*(\w+)', detail, re.IGNORECASE)
    m_data = re.search(r'\bData:\s*(.+?)(?:,\s*\w+:|$)', detail, re.IGNORECASE)
    type_s = m_type.group(1) if m_type else ""
    data_s = m_data.group(1).strip() if m_data else detail.strip()
    return f"[{type_s}] {data_s}" if type_s else data_s


def _derive_reg_diff_from_procmon(events) -> list:
    """filtered_events RegSetValue/RegCreateKey 이벤트 → 스냅샷 비교 형식 목록.

    반환: [(key_path, value_name, value_data, proc_label), ...] 중복 제거 (마지막 쓰기 기준)
    """
    from parsers.procmon_csv import EventCategory
    seen: dict[tuple, tuple] = {}
    for ev in events:
        if ev.category != EventCategory.REGISTRY:
            continue
        if ev.result != "SUCCESS":
            continue
        proc_label = f"{ev.process} ({ev.pid})" if ev.process else ""
        if ev.operation == "RegSetValue":
            path = ev.path or ""
            idx  = path.rfind("\\")
            key_path = path[:idx]  if idx > 0 else path
            val_name = path[idx+1:] if idx > 0 else ""
            val_data = _reg_parse_detail(ev.detail or "")
            seen[(key_path, val_name)] = (key_path, val_name, val_data, proc_label)
        elif ev.operation == "RegCreateKey":
            path = ev.path or ""
            seen[(path, "")] = (path, "(키 생성)", "", proc_label)
    return list(seen.values())


def _registry_events_html(result) -> str:
    from parsers.procmon_csv import EventCategory
    _REG_OPS = ("RegSetValue", "RegCreateKey", "RegDeleteValue", "RegDeleteKey")
    events = [e for e in result.filtered_events if e.category == EventCategory.REGISTRY
              and e.operation in _REG_OPS]
    reg_diff = result.registry_diff
    added    = list(reg_diff.get("added",    []))
    modified = list(reg_diff.get("modified", []))

    # winreg 스냅샷이 비어있으면 ProcMon 이벤트에서 변화 도출
    _from_procmon = False
    if not (added or modified) and events:
        _derived = _derive_reg_diff_from_procmon(events)
        if _derived:
            added = _derived
            _from_procmon = True

    parts = []
    _REG_DIFF_LIMIT = 500
    _REG_EV_LIMIT   = 3000

    # 스냅샷 비교 섹션
    if added or modified:
        total_diff = len(added) + len(modified)
        _src_note = (
            "<span style='font-size:.75rem;color:#6e7681'> (winreg 감시 범위 밖 — ProcMon 기반 도출)</span>"
            if _from_procmon else ""
        )
        rows = []
        for entry in added[:_REG_DIFF_LIMIT]:
            k, n, v = entry[0], entry[1], entry[2]
            proc = entry[3] if len(entry) > 3 else ""
            proc_td = (f"<td class='mono ev-process' style='font-size:0.72rem'>{_e(proc)}</td>"
                       if proc else "<td style='color:#8b949e'>-</td>")
            rows.append(f"<tr><td>{_b('추가','green')}</td>"
                     f"<td class='mono ev-registry'>{_e(k)}</td>"
                     f"<td class='mono'>{_e(n)}</td>"
                     f"<td class='mono' style='color:#8b949e'>{_e(str(v)[:80])}</td>"
                     f"{proc_td}</tr>")
        for entry in modified[:_REG_DIFF_LIMIT]:
            k, n, nw = entry[0], entry[1], entry[3]
            proc = entry[4] if len(entry) > 4 else ""
            proc_td = (f"<td class='mono ev-process' style='font-size:0.72rem'>{_e(proc)}</td>"
                       if proc else "<td style='color:#8b949e'>-</td>")
            rows.append(f"<tr><td>{_b('변경','orange')}</td>"
                     f"<td class='mono ev-registry'>{_e(k)}</td>"
                     f"<td class='mono'>{_e(n)}</td>"
                     f"<td class='mono' style='color:#8b949e'>{_e(str(nw)[:80])}</td>"
                     f"{proc_td}</tr>")
        parts.append(
            f"<h3>레지스트리 스냅샷 비교{_src_note}</h3>"
            + _trunc_notice(total_diff, _REG_DIFF_LIMIT)
            + "<table id='tbl-reg-diff'><tr><th>변경</th><th>키 경로</th><th>값 이름</th><th>데이터</th><th>프로세스</th></tr>"
            + "".join(rows) + "</table>"
        )

    # ProcMon 이벤트
    if events:
        rows = []
        for e in events[:_REG_EV_LIMIT]:
            rows.append(
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
            + "".join(rows) + "</table>"
        )

    return "\n".join(parts) if parts else "<p class='alert alert-success'>레지스트리 변경 없음</p>"


def _fmt_bytes(n: int) -> str:
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f} MB"
    if n >= 1_000:
        return f"{n/1_000:.1f} KB"
    return f"{n} B"


def _proc_cell(procs: list[str], reason: str = "") -> str:
    """프로세스 목록 → <td> HTML. 빈 경우 미확인 배지 반환."""
    if procs:
        return "<td>" + "<br>".join(
            f"<span class='ev-process mono' style='font-size:0.72rem'>{_e(p)}</span>"
            for p in procs[:3]
        ) + "</td>"
    if reason:
        # tooltip에 개행 표시를 위해 &#10; 사용
        _tip = _e(reason).replace("\n", "&#10;")
        return (
            f"<td title='{_tip}' style='cursor:help'>"
            f"<span style='color:#6e7681;font-size:.7rem;border:1px solid #30363d;"
            f"border-radius:3px;padding:1px 4px'>미확인</span>"
            f"</td>"
        )
    return "<td style='color:#484f58'>-</td>"


def _pnmap_debug_panel(pnmap: list, ip_proc_lookup: dict) -> str:
    """process_network_map 진단 패널 HTML."""
    if not pnmap:
        return (
            "<details open style='margin:.5rem 0 1rem;"
            "background:rgba(255,123,114,.07);border:1px solid #ff7b72;"
            "border-radius:6px;padding:.5rem .75rem'>"
            "<summary style='color:#ff7b72;font-size:.82rem;cursor:pointer;font-weight:600'>"
            "⚠ 프로세스 매핑 없음 — process_network_map 비어있음</summary>"
            "<p style='font-size:.78rem;color:#8b949e;margin:.4rem 0 0'>"
            "ProcMon CSV에 TCP/UDP 네트워크 이벤트가 없습니다.<br>"
            "원인: ProcMon 디스플레이 필터에서 Network 카테고리 비활성화.<br>"
            "<code style='font-size:.75rem'>procmon.csv</code> 에서 "
            "<code>TCP Connect</code> / <code>TCP Send</code> 행 존재 여부를 확인하세요.<br>"
            "netstat 스냅샷도 캡처되지 않았거나 분석 중 연결이 없었습니다."
            "</p></details>"
        )

    sample_rows = []
    for _pn in pnmap[:8]:
        sample_rows.append(
            f"<tr><td class='mono' style='font-size:.72rem'>{_e(_pn.process)}</td>"
            f"<td style='color:#8b949e;font-size:.72rem'>({_pn.pid})</td>"
            f"<td class='mono' style='font-size:.72rem'>{_e(_pn.proto)}</td>"
            f"<td class='mono' style='font-size:.72rem'>{_e(_pn.remote_ip)}:{_pn.remote_port}</td>"
            f"<td style='color:#8b949e;font-size:.72rem'>{_pn.event_count}회</td></tr>"
        )
    more = len(pnmap) - 8
    return (
        f"<details style='margin:.5rem 0 1rem'>"
        f"<summary style='color:#56d364;font-size:.8rem;cursor:pointer'>"
        f"✓ 프로세스 매핑 {len(pnmap)}개 / IP 룩업 키 {len(ip_proc_lookup)}개 (클릭하여 샘플 보기)</summary>"
        f"<table style='margin-top:.4rem;border-collapse:collapse'>"
        f"<tr><th style='font-size:.72rem'>프로세스</th><th></th><th>Proto</th>"
        f"<th>Remote</th><th>횟수</th></tr>"
        + "".join(sample_rows)
        + (f"<tr><td colspan='5' style='color:#6e7681;font-size:.72rem'>… {more}개 더</td></tr>"
           if more > 0 else "")
        + "</table></details>"
    )


def _network_html(result) -> str:
    pcap = result.pcap_result

    # pcap이 없어도 decrypted_requests / fakenet_result는 렌더링해야 하므로
    # 조기 리턴하지 않고 각 섹션을 독립적으로 처리한다.

    # ── 공통 조회 테이블 (pcap 있을 때만 빌드) ────────────────────
    combined_domains: dict[str, list[str]] = {}
    if pcap:
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
    pnmap = getattr(result, "process_network_map", [])
    proc_lookup: dict[tuple, list[str]] = {}
    ip_proc_lookup: dict[str, list[str]] = {}
    # ① 로컬 포트 역추적: local_port → 프로세스 목록
    local_port_lookup: dict[int, list[str]] = {}
    # ② 음수 귀속: 프로세스별 알려진 remote_ip 집합
    proc_known_ips: dict[str, set[str]] = {}

    for _pn in pnmap:
        _label = f"{_pn.process} ({_pn.pid})"
        _key   = (_pn.proto.upper(), _pn.remote_ip, _pn.remote_port)
        proc_lookup.setdefault(_key, [])
        if _label not in proc_lookup[_key]:
            proc_lookup[_key].append(_label)
        _ip_lst = ip_proc_lookup.setdefault(_pn.remote_ip, [])
        if _label not in _ip_lst:
            _ip_lst.append(_label)

        # ③ 호스트명 역매핑: ProcMon이 hostname으로 기록한 경우 IP로 확장
        for _mapped_ip in hostname_to_ips.get(_pn.remote_ip.lower(), []):
            _ip_key = (_pn.proto.upper(), _mapped_ip, _pn.remote_port)
            proc_lookup.setdefault(_ip_key, [])
            if _label not in proc_lookup[_ip_key]:
                proc_lookup[_ip_key].append(_label)
            _ip2_lst = ip_proc_lookup.setdefault(_mapped_ip, [])
            if _label not in _ip2_lst:
                _ip2_lst.append(_label)

        # ① local_port 역추적 등록
        _lp = getattr(_pn, "local_port", 0)
        if _lp:
            _lp_lst = local_port_lookup.setdefault(_lp, [])
            if _label not in _lp_lst:
                _lp_lst.append(_label)

        # ② 음수 귀속용: 프로세스별 알려진 IP 수집
        _proc_key = _pn.process.lower()
        proc_known_ips.setdefault(_proc_key, set()).add(_pn.remote_ip)
        for _mip in hostname_to_ips.get(_pn.remote_ip.lower(), []):
            proc_known_ips[_proc_key].add(_mip)

    parts = []

    # pcap 없으면 기본 안내 배너만 추가 (decrypted/fakenet은 계속 처리)
    if not pcap:
        parts.append("<p class='alert alert-info'>tshark 캡처 없음 — PCAP 기반 섹션 생략</p>")

    if pcap:
        # ── 프로세스 매핑 진단 패널 ──────────────────────────────────
        parts.append(_pnmap_debug_panel(pnmap, ip_proc_lookup))

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
        rows = []
        for b in beacons[:100]:
            b_procs = (proc_lookup.get(("TCP", b.dst_ip, b.dst_port), [])
                       or proc_lookup.get(("UDP", b.dst_ip, b.dst_port), []))
            rows.append(
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
            + "".join(rows) + "</table>"
        )

    # ── TLS SNI ────────────────────────────────────────────────
    tls_list = getattr(pcap, "tls_info", [])
    if tls_list:
        # SNI 기준 dedup — 같은 SNI가 여러 연결에서 나오면 첫 번째 보존
        seen: dict = {}
        for t in tls_list:
            key = (t.sni, t.dst_ip, t.dst_port)
            if key not in seen:
                seen[key] = t
        _TLS_LIMIT = 500
        seen_vals  = list(seen.values())
        rows = []
        for t in seen_vals[:_TLS_LIMIT]:
            t_procs = proc_lookup.get(("TCP", t.dst_ip, t.dst_port), [])
            # JA3 표시: 알려진 레이블이 있으면 붉은 배지, 없으면 해시 앞 12자
            ja3_label = getattr(t, "ja3_label", "")
            ja3_hash  = getattr(t, "ja3", "")
            tls_ver   = getattr(t, "tls_version", "")
            if ja3_label:
                ja3_td = f"<td>{_b(ja3_label, 'red')}</td>"
            elif ja3_hash:
                ja3_td = (
                    f"<td><span class='mono' style='font-size:.72rem;color:#8b949e' "
                    f"title='{_e(ja3_hash)}'>{ja3_hash[:12]}…</span></td>"
                )
            else:
                ja3_td = "<td style='color:#484f58'>-</td>"
            rows.append(
                f"<tr>"
                f"<td class='mono ev-network'>{_e(t.sni)}</td>"
                f"<td class='mono'>{_e(t.dst_ip)}</td>"
                f"<td class='mono'>{t.dst_port}</td>"
                f"<td class='mono' style='color:#8b949e;font-size:.78rem'>{_e(tls_ver) or '-'}</td>"
                f"{ja3_td}"
                + _proc_cell(t_procs) +
                f"</tr>"
            )
        parts.append(
            "<h3>🔒 TLS SNI (HTTPS 도메인)</h3>"
            + _trunc_notice(len(seen_vals), _TLS_LIMIT)
            + "<table id='tbl-net-tls'><tr><th>SNI 도메인</th><th>목적지 IP</th><th>포트</th>"
            "<th>TLS 버전</th><th>JA3</th><th>프로세스</th></tr>"
            + "".join(rows) + "</table>"
        )

    # ── DGA / 의심 도메인 ──────────────────────────────────────
    susp_domains = getattr(pcap, "suspicious_domains", [])
    if susp_domains:
        rows = []
        for d in susp_domains[:50]:
            dga_procs: list[str] = []
            for _dip in hostname_to_ips.get(d.lower(), []):
                for _p in ip_proc_lookup.get(_dip, []):
                    if _p not in dga_procs:
                        dga_procs.append(_p)
            rows.append(
                f"<tr>"
                f"<td class='mono' style='color:#ff7b72'>{_e(d)}</td>"
                + _proc_cell(dga_procs) +
                f"</tr>"
            )
        parts.append(
            "<h3>⚠ DGA / 고엔트로피 도메인</h3>"
            + f"<table id='tbl-net-dga'><tr><th>도메인</th><th>프로세스</th></tr>" + "".join(rows) + "</table>"
        )

    # ── 연결 목록 ──────────────────────────────────────────────
    if pcap and pcap.connections:
        _CONN_LIMIT = 1000
        sorted_conns = sorted(pcap.connections, key=lambda x: -x.bytes_out)
        rows = []
        for c in sorted_conns[:_CONN_LIMIT]:
            ext = not _is_private_ip_str(c.dst_ip)
            ip_color = "ev-network" if ext else ""
            susp_badge = _b("!", "red") if c.suspicious_port else ""
            _PORT_NOTE = {5228: "FCM"}  # Firebase Cloud Messaging — RAT C2 채널 악용
            port_note = (f" <span style='font-size:.7rem;color:#e3b341'>"
                         f"{_PORT_NOTE[c.dst_port]}</span>"
                         if c.dst_port in _PORT_NOTE else "")

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

            # 프로세스 lookup — 3단계 순서로 시도
            if _is_private_ip_str(c.dst_ip):
                _lookup_ip  = c.src_ip
                _conn_procs = ip_proc_lookup.get(c.src_ip, [])
            else:
                _lookup_ip  = c.dst_ip
                # 1단계: (proto, dst_ip, dst_port) 정확 매핑
                _conn_procs = proc_lookup.get((c.proto.upper(), c.dst_ip, c.dst_port), [])
                # 2단계: dst_ip 단독 매핑 (포트 불일치 허용)
                if not _conn_procs:
                    _conn_procs = ip_proc_lookup.get(c.dst_ip, [])
                # 3단계: 로컬 포트 역추적 (src_port → ProcMon local_port 매핑)
                _c_src_port = getattr(c, "src_port", 0)
                if not _conn_procs and _c_src_port:
                    _conn_procs = local_port_lookup.get(_c_src_port, [])

            # 음수 귀속: 미확인이지만 어떤 알려진 프로세스가 아닌지 계산
            _neg_hint = ""
            if not _conn_procs and pnmap and not _is_private_ip_str(c.dst_ip):
                _excluded = [
                    proc for proc, known in proc_known_ips.items()
                    if c.dst_ip not in known
                ]
                if _excluded and len(_excluded) < len(proc_known_ips):
                    # 일부 프로세스에서 제외됨 → 나머지 프로세스 후보
                    _candidates = [
                        proc for proc, known in proc_known_ips.items()
                        if c.dst_ip in known
                    ]
                    if not _candidates:
                        _neg_hint = f" (알려진 프로세스 {len(proc_known_ips)}개 모두 아님)"

            if not _conn_procs:
                if not pnmap:
                    _reason = "ProcMon Network 이벤트 없음 — ProcMon 필터에서 Network 카테고리 활성화 필요"
                else:
                    _reason = (
                        f"ProcMon 미캡처{_neg_hint}\n"
                        "가능한 원인: ① 프로세스 인젝션 후 타 프로세스 명의로 통신 "
                        "② WMI/COM을 통한 우회 통신 ③ 원시 소켓(Raw socket) 사용 "
                        "④ ProcMon 시작 전 이미 연결 성립"
                    )
            else:
                _reason = ""
            rows.append(
                f"<tr>"
                f"<td>{_b(c.proto, 'blue')}</td>"
                f"<td class='mono'>{_e(c.src_ip)}</td>"
                f"<td class='mono {ip_color}'>{_e(c.dst_ip)}</td>"
                f"{dom_td}"
                f"<td class='mono'>{c.dst_port}{port_note} {susp_badge}</td>"
                f"<td style='color:#8b949e'>{c.count}</td>"
                f"<td class='mono'>{_fmt_bytes(c.bytes_out)}</td>"
                + _proc_cell(_conn_procs, _reason) +
                f"</tr>"
            )
        parts.append(
            "<h3>네트워크 연결 (송신량 순)</h3>"
            + _trunc_notice(len(pcap.connections), _CONN_LIMIT)
            + "<table id='tbl-net-conn'><tr><th>프로토콜</th><th>출발지 IP</th><th>목적지 IP</th>"
            "<th>도메인</th><th>포트</th><th>횟수</th><th>송신량</th><th>프로세스</th></tr>"
            + "".join(rows) + "</table>"
        )

    # ── DNS 쿼리 ───────────────────────────────────────────────
    if pcap and pcap.dns_queries:
        _DNS_LIMIT   = 1000
        sorted_dns   = sorted(pcap.dns_queries, key=lambda x: -x.entropy)
        rows = []
        for q in sorted_dns[:_DNS_LIMIT]:
            dns_procs: list[str] = []
            for rip in q.response_ips[:5]:
                for p in ip_proc_lookup.get(rip, []):
                    if p not in dns_procs:
                        dns_procs.append(p)
            # 의심 배지 조합
            susp_badges = ""
            if q.suspicious:
                susp_badges += _b("DGA?", "red")
            if getattr(q, "is_ddns", False):
                susp_badges += _b("DDNS", "orange")
            if getattr(q, "no_response", False):
                susp_badges += _b("응답없음", "yellow")
            _q_is_ddns = getattr(q, "is_ddns", False)
            _q_cls  = "" if (q.suspicious or _q_is_ddns) else "ev-network"
            _q_clr  = "color:#ff7b72" if q.suspicious else ("color:#ffa657" if _q_is_ddns else "")
            _q_rips = _e(", ".join(q.response_ips[:3])) if q.response_ips else "<span style='color:#8b949e;font-size:.72rem'>—</span>"
            rows.append(
                f"<tr>"
                f"<td class='mono {_q_cls}' style='{_q_clr}'>{_e(q.name)}</td>"
                f"<td class='mono' style='color:#8b949e'>{_e(q.qtype)}</td>"
                f"<td class='mono' style='color:#8b949e'>{q.entropy:.2f}</td>"
                f"<td class='mono' style='color:#56d364;font-size:0.72rem'>{_q_rips}</td>"
                f"<td>{susp_badges}</td>"
                + _proc_cell(dns_procs) +
                f"</tr>"
            )
        parts.append(
            "<h3>DNS 쿼리 (엔트로피 순)</h3>"
            + _trunc_notice(len(pcap.dns_queries), _DNS_LIMIT)
            + "<table id='tbl-net-dns'><tr><th>도메인</th><th>타입</th><th>엔트로피</th>"
            "<th>응답 IP</th><th>의심</th><th>프로세스</th></tr>"
            + "".join(rows) + "</table>"
        )

    # ── HTTP 요청 ──────────────────────────────────────────────
    if pcap and pcap.http_requests:
        _HTTP_LIMIT = 500
        rows = []
        for _hi, r in enumerate(pcap.http_requests[:_HTTP_LIMIT]):
            # 프로세스 룩업: dst_ip 직접 사용 → hostname 역매핑 순서로 시도
            h_procs: list[str] = []
            _r_dst_ip = getattr(r, "dst_ip", "")
            _r_dst_port = getattr(r, "dst_port", 80)
            if _r_dst_ip:
                h_procs = (
                    proc_lookup.get(("TCP", _r_dst_ip, _r_dst_port), [])
                    or ip_proc_lookup.get(_r_dst_ip, [])
                )
            if not h_procs:
                for hname in hostname_to_ips.get(r.host.lower(), []):
                    for p in ip_proc_lookup.get(hname, []):
                        if p not in h_procs:
                            h_procs.append(p)

            # 상세 패널 (헤더 + 바디)
            _detail_rows = []
            if _r_dst_ip:
                _detail_rows.append(f"<b>목적지</b> {_e(_r_dst_ip)}:{_r_dst_port}")
            if r.referer:
                _detail_rows.append(f"<b>Referer</b> {_e(r.referer[:120])}")
            _r_ct = getattr(r, "content_type", "")
            if _r_ct:
                _detail_rows.append(f"<b>Content-Type</b> {_e(_r_ct)}")
            _r_auth = getattr(r, "authorization", "")
            if _r_auth:
                _detail_rows.append(
                    f"<b style='color:#ff7b72'>Authorization</b> "
                    f"<span style='color:#ffa657'>{_e(_r_auth[:80])}</span>"
                )
            _r_extra = getattr(r, "extra_headers", "")
            if _r_extra:
                _detail_rows.append(f"<b>기타헤더</b> {_e(_r_extra[:120])}")
            _r_body = getattr(r, "body_preview", "")
            if _r_body:
                _detail_rows.append(
                    f"<b>Body</b><br><pre style='margin:.2rem 0 0;font-size:.72rem;"
                    f"background:#0d1117;padding:.4rem;border-radius:4px;overflow-x:auto;"
                    f"max-width:600px;white-space:pre-wrap'>{_e(_r_body[:512])}</pre>"
                )

            _detail_html = ""
            if _detail_rows:
                _detail_id = f"hreq-{_hi}"
                _detail_html = (
                    f"<details id='{_detail_id}' style='margin:.1rem 0'>"
                    f"<summary style='font-size:.72rem;color:#8b949e;cursor:pointer'>상세 보기</summary>"
                    f"<div style='font-size:.75rem;padding:.3rem .5rem;line-height:1.6'>"
                    + "<br>".join(_detail_rows)
                    + "</div></details>"
                )

            # 호버시 전체 URL 복사가 가능하도록 title 속성에 full URL 포함
            _full_url = f"http://{r.host}{r.path}"
            _path_display = _e(r.path[:300]) or "/"
            rows.append(
                f"<tr>"
                f"<td>{_b(r.method,'orange')}</td>"
                f"<td class='mono'>{_e(r.host)}</td>"
                f"<td class='mono ev-network' style='word-break:break-all;min-width:180px'>"
                f"<span title='{_e(_full_url)}'>{_path_display}</span>"
                f"{_detail_html}</td>"
                f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(r.user_agent[:80])}</td>"
                f"<td class='mono'>{_fmt_bytes(r.content_length) if r.content_length else '-'}</td>"
                f"<td>{'🍪' if r.has_cookie else ''}</td>"
                + _proc_cell(h_procs) +
                f"</tr>"
            )
        parts.append(
            "<h3>HTTP 요청</h3>"
            + _trunc_notice(len(pcap.http_requests), _HTTP_LIMIT)
            + "<table id='tbl-net-http'><tr><th>메서드</th><th>호스트</th><th>경로</th>"
            "<th>User-Agent</th><th>Body크기</th><th>Cookie</th><th>프로세스</th></tr>"
            + "".join(rows) + "</table>"
        )

    # ── SMTP C2 세션 (AgentTesla 등 자격증명 탈취 악성코드) ─────────
    smtp_sessions = getattr(pcap, "smtp_sessions", [])
    if smtp_sessions:
        rows = []
        for s in smtp_sessions:
            auth_badge  = _b("AUTH", "red")   if s.has_auth else ""
            data_badge  = _b("DATA", "orange") if s.has_data else ""
            smtp_procs  = proc_lookup.get(("TCP", s.dst_ip, s.dst_port), [])
            rows.append(
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
            + "".join(rows) + "</table>"
        )

    # ── FTP C2 세션 ────────────────────────────────────────────
    ftp_sessions = getattr(pcap, "ftp_sessions", [])
    if ftp_sessions:
        rows = []
        for s in ftp_sessions:
            auth_badge = _b("AUTH", "red") if s.has_auth else ""
            ftp_procs  = proc_lookup.get(("TCP", s.dst_ip, s.dst_port), [])
            rows.append(
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
            + "".join(rows) + "</table>"
        )

    # ── HTTPS 복호화 (SSLKEYLOGFILE) ─────────────────────────────
    decrypted = getattr(result, "decrypted_requests", []) or []
    if decrypted:
        _DEC_LIMIT = 300
        rows = []
        for req in decrypted[:_DEC_LIMIT]:
            method   = _e(getattr(req, "method", "") or "")
            host     = _e(getattr(req, "host", "") or "")
            path     = _e((getattr(req, "path", "") or "")[:80])
            ua       = _e((getattr(req, "user_agent", "") or "")[:60])
            status   = str(getattr(req, "resp_status", "") or "")
            ct_resp  = _e(getattr(req, "resp_content_type", "") or "")
            if status.startswith("2"):
                st_color = "color:#56d364"
            elif status.startswith("3"):
                st_color = "color:#e3b341"
            else:
                st_color = "color:#ff7b72" if status else "color:#8b949e"
            rows.append(
                f"<tr>"
                f"<td>{_b(method, 'orange')}</td>"
                f"<td class='mono ev-network'>{host}</td>"
                f"<td class='mono'>{path}</td>"
                f"<td class='mono' style='color:#8b949e;font-size:.72rem'>{ua}</td>"
                f"<td class='mono' style='{st_color}'>{status or '-'}</td>"
                f"<td class='mono' style='color:#8b949e;font-size:.72rem'>{ct_resp}</td>"
                f"</tr>"
            )
        parts.append(
            f"<h3>🔓 HTTPS 복호화 요청 ({len(decrypted)}건)</h3>"
            f"<p style='color:#8b949e;font-size:.78rem;margin-bottom:.5rem'>"
            f"SSLKEYLOGFILE 기반 TLS 복호화 — Python/Go/NSS TLS 구현에서만 작동 "
            f"(Schannel/WinHTTP 기반 악성코드는 FakeNet-NG 사용)</p>"
            + _trunc_notice(len(decrypted), _DEC_LIMIT)
            + "<table id='tbl-net-dec'>"
            "<tr><th>메서드</th><th>호스트</th><th>경로</th><th>User-Agent</th>"
            "<th>응답 코드</th><th>응답 Content-Type</th></tr>"
            + "".join(rows) + "</table>"
        )

    # ── FakeNet-NG 캡처 ──────────────────────────────────────────
    fn = getattr(result, "fakenet_result", {}) or {}
    fn_err   = fn.get("error", "")
    fn_dns   = fn.get("dns_queries",   []) or []
    fn_http  = fn.get("http_requests", []) or []
    fn_tcp   = fn.get("tcp_sessions",  []) or []
    if fn and (fn_dns or fn_http or fn_tcp):
        fn_elapsed = fn.get("elapsed_sec", 0)
        err_html = f'&nbsp;|&nbsp; <span style="color:#ff7b72">{_e(fn_err)}</span>' if fn_err else ''
        fn_parts = [
            f"<h3>🎭 FakeNet-NG 캡처</h3>"
            f"<p style='color:#8b949e;font-size:.82rem;margin-bottom:1rem'>"
            f"실행 {fn_elapsed}s &nbsp;|&nbsp; DNS {len(fn_dns)}건 &nbsp;|&nbsp; "
            f"HTTP {len(fn_http)}건 &nbsp;|&nbsp; 바이너리 TCP {len(fn_tcp)}건"
            f"{err_html}"
            f"</p>"
        ]
        if fn_dns:
            rows = "".join(
                f"<tr>"
                f"<td class='mono ev-network'>{_e(d.get('domain',''))}</td>"
                f"<td class='mono' style='color:#56d364'>{_e(d.get('resolved','127.0.0.1'))}</td>"
                f"</tr>"
                for d in fn_dns[:200]
            )
            fn_parts.append(
                "<h4>DNS 쿼리</h4>"
                "<table id='tbl-fn-dns'><tr><th>쿼리 도메인</th><th>응답 IP</th></tr>"
                + rows + "</table>"
            )
        if fn_http:
            rows = "".join(
                f"<tr>"
                f"<td>{_b(h.get('proto','HTTP'), 'blue' if h.get('proto','HTTP') == 'HTTP' else 'orange')}</td>"
                f"<td>{_b(h.get('method',''), 'orange')}</td>"
                f"<td class='mono ev-network'>{_e(h.get('host',''))}</td>"
                f"<td class='mono'>{_e((h.get('path','') or '')[:80])}</td>"
                f"<td class='mono' style='color:#8b949e;font-size:.72rem'>{_e((h.get('user_agent','') or '')[:50])}</td>"
                f"</tr>"
                for h in fn_http[:300]
            )
            fn_parts.append(
                "<h4>HTTP / HTTPS 요청 <span style='color:#8b949e;font-size:.78rem'>"
                "(FakeNet-NG가 TLS 종단 — Schannel/WinHTTP 포함)</span></h4>"
                "<table id='tbl-fn-http'><tr><th>프로토콜</th><th>메서드</th>"
                "<th>호스트</th><th>경로</th><th>User-Agent</th></tr>"
                + rows + "</table>"
            )
        if fn_tcp:
            rows = "".join(
                f"<tr>"
                f"<td class='mono'>{_e(t.get('src_ip',''))}</td>"
                f"<td class='mono'>{t.get('dst_port','')}</td>"
                f"</tr>"
                for t in fn_tcp[:100]
            )
            fn_parts.append(
                "<h4>바이너리 TCP 세션 (C2 커스텀 프로토콜)</h4>"
                "<table id='tbl-fn-tcp'><tr><th>출발지 IP</th><th>목적지 포트</th></tr>"
                + rows + "</table>"
            )
        parts.append("".join(fn_parts))

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

    rows = []
    for p in new_procs:
        cmdline = " ".join(p.cmdline) if p.cmdline else ""
        rows.append(
            f"<tr>"
            f"<td class='mono'>{p.pid}</td>"
            f"<td class='mono ev-process'>{_e(p.name)}</td>"
            f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(p.exe or '')}</td>"
            f"<td class='mono' style='color:#8b949e;font-size:0.72rem'>{_e(cmdline[:120])}</td>"
            f"</tr>"
        )
    table_html = (
        "<table id='tbl-process'><tr><th>PID</th><th>프로세스</th><th>경로</th><th>명령줄</th></tr>"
        + "".join(rows) + "</table>"
    )

    # ── 전체 프로세스 기록 (화이트리스트 오탐만 제외) ────────────────
    all_procs_html = _all_procs_html(result, chain_pids={p.pid for p in new_procs})

    return tree_html + excl_note + table_html + all_procs_html


def _all_procs_html(result, chain_pids: set) -> str:
    """화이트리스트 오탐만 제외한 신규 프로세스 전체 기록 테이블."""
    all_new = result.process_diff.get("new_processes", [])
    _WL = frozenset()
    table_procs = [p for p in all_new if p.name.lower() not in _WL]
    wl_excl = len(all_new) - len(table_procs)

    note = (
        f"<p style='font-size:.78rem;color:#6e7681;margin:1.2rem 0 .4rem'>"
        f"<strong style='color:#cdd9e5'>전체 프로세스 기록</strong>"
        f"&nbsp;— 오탐(화이트리스트) {wl_excl}개 제외 · {len(table_procs)}개"
        f"&nbsp;·&nbsp;<span style='opacity:.5'>흐린 행</span> = 악성 체인 외부</p>"
    )

    rows = []
    for p in table_procs:
        cmdline = " ".join(p.cmdline) if p.cmdline else ""
        tr_open = "<tr>" if p.pid in chain_pids else "<tr style='opacity:.45'>"
        rows.append(
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
        + "".join(rows)
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
    rows = []
    for mod in proc.modules:
        mod_name  = Path(mod.module_path).name if mod.module_path else "-"
        dump_name = Path(mod.dump_file).name   if mod.dump_file   else "-"
        if mod.is_shellcode:
            kind_badge = _b("쉘코드", "red")
        elif mod.implanted_count:
            kind_badge = _b("PE 인젝션", "orange")
        else:
            kind_badge = _b("훅/패치", "yellow")
        rows.append(
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
        + "".join(rows) + "</table>"
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
        rows = []
        if has_hh_data:
            ss = "#ff7b72" if hh_susp   else "#56d364"
            pi = "#e3b341" if hh_pe_inj else "#8b949e"
            sc = "#ff7b72" if hh_shc    else "#8b949e"
            rows.append(
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
            rows.append(
                f"<tr><td>pe-sieve (신규 + 의심 DLL 로드 프로세스)</td><td>"
                f"{len(pe_valid)}개 스캔 &nbsp;"
                f"<b style='color:{pss}'>의심 {len(pe_susp)}개</b> &nbsp;"
                f"<b style='color:{ppi}'>PE인젝션 {pe_pe_inj}개</b> &nbsp;"
                f"<b style='color:{psc}'>쉘코드 {pe_shc}개</b>"
                f"</td></tr>"
            )
        parts.append(
            f"<div class='card' style='margin-bottom:1rem'>"
            f"<table class='kv'>{''.join(rows)}</table>"
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

    # ── 프로세스 매핑 조회 테이블 구성 (IP/도메인 테이블 렌더 전 선행 빌드) ──
    hostname_to_ips: dict[str, list[str]] = {}
    for _ip, _doms in combined_dom.items():
        for _d in _doms:
            hostname_to_ips.setdefault(_d.lower(), []).append(_ip)

    pnmap = getattr(result, "process_network_map", [])
    ip_proc_lookup: dict[str, list[str]] = {}
    for _pn in pnmap:
        _label = f"{_pn.process} ({_pn.pid})"
        _ipl = ip_proc_lookup.setdefault(_pn.remote_ip, [])
        if _label not in _ipl:
            _ipl.append(_label)
        for _mip in hostname_to_ips.get(_pn.remote_ip.lower(), []):
            _mipl = ip_proc_lookup.setdefault(_mip, [])
            if _label not in _mipl:
                _mipl.append(_label)

    parts.append(_pnmap_debug_panel(pnmap, ip_proc_lookup))

    # ── 외부 IP 테이블 (풍부한 컬럼) ─────────────────────────────
    if ioc.ip_addresses:
        pub_ips = ioc.ip_addresses[:_IOC_LIMIT]
        rows = []
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
            rows.append(
                f"<tr>"
                f"<td class='mono ev-network'>{_e(ip)}</td>"
                f"<td>{dom_html}</td>"
                f"<td style='white-space:nowrap'>{port_html}</td>"
                f"<td data-geo-ip='{_e(ip)}' style='color:#8b949e;font-size:.78rem'>"
                f"<span style='color:#484f58'>…</span></td>"
                + _proc_cell(ip_proc_lookup.get(ip, [])) +
                f"</tr>"
            )
        geo_ips_js = _json.dumps(pub_ips[:100])
        parts.append(
            "<h3>외부 IP</h3>"
            + _trunc_notice(len(ioc.ip_addresses), _IOC_LIMIT)
            + "<table id='tbl-ioc-ip'>"
            + "<tr><th>IP 주소</th><th>연관 도메인</th><th>포트</th><th>국가 / 기관</th><th>프로세스</th></tr>"
            + "".join(rows) + "</table>"
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

    # 파일 이벤트 → 파일경로(소문자): 프로세스 매핑
    # WriteFile + CreateFile+Created + RenameFile(목적지) 모두 포함
    file_proc_map: dict[str, list[str]] = {}
    try:
        from parsers.procmon_csv import EventCategory as _EC
        _RENAME_DEST_RE2 = __import__('re').compile(r'FileName:\s*([^,\r\n]+)', __import__('re').IGNORECASE)
        for _ev in getattr(result, "filtered_events", []):
            if _ev.category != _EC.FILE:
                continue
            _label = f"{_ev.process} ({_ev.pid})"
            if _ev.operation == "WriteFile" and _ev.result == "SUCCESS":
                _lp = _ev.path.lower()
                _lst = file_proc_map.setdefault(_lp, [])
                if _label not in _lst:
                    _lst.append(_label)
            elif _ev.operation == "CreateFile" and _ev.result == "SUCCESS" and "OpenResult: Created" in (_ev.detail or ""):
                _lp = _ev.path.lower()
                _lst = file_proc_map.setdefault(_lp, [])
                if _label not in _lst:
                    _lst.append(_label)
            elif _ev.operation == "RenameFile" and _ev.result == "SUCCESS":
                _m = _RENAME_DEST_RE2.search(_ev.detail or "")
                if _m:
                    _lp = _m.group(1).strip().lower()
                    _lst = file_proc_map.setdefault(_lp, [])
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

    if ioc.domains:
        _dom_rows = []
        for _dom in ioc.domains[:_IOC_LIMIT]:
            _dom_procs: list[str] = []
            for _dip in hostname_to_ips.get(_dom.lower(), []):
                for _p in ip_proc_lookup.get(_dip, []):
                    if _p not in _dom_procs:
                        _dom_procs.append(_p)
            _dom_rows.append(
                f"<tr>"
                f"<td class='mono ev-network'>{_e(_dom)}</td>"
                + _proc_cell(_dom_procs) +
                f"</tr>"
            )
        parts.append(
            "<h3>도메인</h3>"
            + _trunc_notice(len(ioc.domains), _IOC_LIMIT)
            + "<table id='tbl-ioc-domain'>"
            + "<tr><th>도메인</th><th>프로세스</th></tr>"
            + "".join(_dom_rows) + "</table>"
        )

    # ── 드롭된 파일 (프로세스 매핑 포함) ──────────────────────────
    if ioc.dropped_files:
        rows = []
        for fp in ioc.dropped_files[:_IOC_LIMIT]:
            procs = file_proc_map.get(fp.lower(), [])
            rows.append(
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
            + "".join(rows) + "</table>"
        )

    parts.append(_list_table("레지스트리 키", ioc.registry_keys, "키 경로", "tbl-ioc-reg"))

    # ── URL (프로세스 매핑 포함) ───────────────────────────────────
    if ioc.urls:
        rows = []
        for url in ioc.urls[:_IOC_LIMIT]:
            procs = url_proc_map.get(url, [])
            rows.append(
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
            + "".join(rows) + "</table>"
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

    # 의심 프로세스 수 집계 (pe-sieve / hollows-hunter 결과 기준)
    shc_total       = 0
    shc_fp_excluded = 0

    if _hh and not _hh.error:
        shc_total += len(_hh.suspicious_processes)

    for _r in _ps_list:
        if not _r.error and _r.suspicious > 0:
            shc_total += 1

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

    def _tool_badge(k: str, v) -> str:
        """bool 또는 문자열 도구 상태를 배지로 변환."""
        if isinstance(v, bool):
            return _b("✔ " + k, "green") if v else _b("✘ " + k, "gray")
        # 문자열 — 내용으로 성공/실패 판별
        s = str(v)
        _negative = ("비활성", "미설치", "없음", "오류", "건너뜀", "실패", "비PE")
        if not s or any(n in s for n in _negative):
            icon, color = "✘", "gray"
        else:
            icon, color = "✔", "green"
        short = s[:28] + "…" if len(s) > 28 else s
        return f"<span title='{_e(s)}'>{_b(f'{icon} {k}: {short}', color)}</span>"

    tools_html = "  ".join(_tool_badge(k, v) for k, v in result.tools_used.items())

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
  <button class="tab-btn" data-tab="tab-ai">
    🤖 AI 분석
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
        <tr><td>TLS 세션 키</td><td>{getattr(result, 'tls_key_count', 0)} <span style='color:#8b949e;font-size:.78rem'>{"(복호화 " + str(len(getattr(result,'decrypted_requests',[]))) + "건)" if getattr(result,'decrypted_requests',None) else ""}</span></td></tr>
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
  {_volatility_html(result)}

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

<!-- ══════════ 탭 8: AI 분석 ══════════ -->
<div id="tab-ai" class="tab-panel">
  {_ai_html(result)}
</div>

</div>
{_PG_INIT}
</body>
</html>"""

    Path(output_path).write_text(body, encoding="utf-8")


# ══════════════════════════════════════════════════════════════════════
# Volatility3 메모리 포렌식 결과 렌더링
# ══════════════════════════════════════════════════════════════════════

def _volatility_html(result) -> str:
    """Volatility3 메모리 포렌식 결과 섹션 렌더링."""
    mf = getattr(result, "mem_forensics", None) or {}
    if not mf:
        return ""

    err = mf.get("error", "")
    if err:
        return (
            f"<div style='margin-top:1.5rem'>"
            f"<h3>🔬 Volatility3 메모리 포렌식</h3>"
            f"<p class='alert alert-warning'>{_e(err)}</p>"
            f"</div>"
        )

    malfind    = mf.get("malfind")   or []
    pstree     = mf.get("pstree")    or []
    netscan    = mf.get("netscan")   or []
    connscan   = mf.get("connscan")  or []
    psxview    = mf.get("psxview")   or []
    cmdline    = mf.get("cmdline")   or []
    handles    = mf.get("handles")   or []
    dlllist    = mf.get("dlllist")   or []
    procdumps  = mf.get("procdumps") or []
    dump_gb       = mf.get("dump_size_gb", 0)
    vol_sec       = mf.get("vol_elapsed", 0)
    plugin_errors = mf.get("plugin_errors") or {}

    parts = [
        f"<div style='margin-top:1.5rem'>",
        f"<h3>🔬 Volatility3 메모리 포렌식</h3>",
        f"<p style='color:#8b949e;font-size:.82rem;margin-bottom:1rem'>"
        f"덤프 {dump_gb} GB &nbsp;|&nbsp; 분석 {vol_sec}s &nbsp;|&nbsp; "
        f"malfind <strong style='color:{'#ff7b72' if malfind else 'inherit'}'>{len(malfind)}</strong>건 &nbsp;|&nbsp; "
        f"netscan {len(netscan)}건 &nbsp;|&nbsp; connscan {len(connscan)}건 &nbsp;|&nbsp; "
        f"psxview 은닉 <strong style='color:{'#ff7b72' if any(e.get('hidden') for e in psxview) else 'inherit'}'>"
        f"{sum(1 for e in psxview if e.get('hidden'))}</strong>건 &nbsp;|&nbsp; "
        f"handles(Mutant) {len(handles)}건 &nbsp;|&nbsp; "
        f"PE 추출 {len(procdumps)}건</p>",
    ]

    # ── 플러그인 오류 표시 ────────────────────────────────────────────
    if plugin_errors:
        err_rows = "".join(
            f"<tr>"
            f"<td class='mono' style='color:#e3b341'>{_e(pname)}</td>"
            f"<td style='font-size:.78rem;color:#8b949e;white-space:pre-wrap'>{_e(pmsg[:300])}</td>"
            f"</tr>"
            for pname, pmsg in plugin_errors.items()
        )
        parts.append(
            f"<details style='margin-bottom:1rem'>"
            f"<summary style='color:#e3b341;cursor:pointer;font-size:.83rem'>"
            f"⚠ 플러그인 오류 {len(plugin_errors)}건 (클릭하여 확인)</summary>"
            f"<div style='overflow-x:auto;margin-top:.5rem'>"
            f"<table><tr><th>플러그인</th><th>오류 메시지</th></tr>{err_rows}</table>"
            f"<p style='color:#8b949e;font-size:.76rem;margin-top:.5rem'>"
            f"💡 심볼 파일 없음 오류 → "
            f"<code>pip install volatility3</code> 후 "
            f"<code>vol -f memory.raw windows.info</code> 로 심볼 자동 다운로드</p>"
            f"</div></details>"
        )

    # 모든 플러그인 결과가 비어있으면 안내
    has_any = any([malfind, pstree, netscan, connscan, psxview, cmdline, handles, dlllist, procdumps])
    if not has_any and not plugin_errors:
        parts.append(
            f"<p style='color:#8b949e;font-size:.83rem;margin-bottom:1rem'>"
            f"분석 결과 없음 — 의심 항목이 탐지되지 않았거나 심볼 파일 미설치로 플러그인이 "
            f"빈 결과를 반환했을 수 있습니다.<br>"
            f"<code>vol -f {mf.get('dump_path','memory.raw')} windows.info</code> 로 덤프 유효성 확인 권장</p>"
        )

    # ── malfind ──────────────────────────────────────────────────────
    if malfind:
        rows = ""
        for e in malfind[:50]:
            prot = _e(e.get("protection", ""))
            rw   = "PAGE_EXECUTE_READWRITE" in prot or "PAGE_EXECUTE_WRITECOPY" in prot
            prot_cell = (f"<span style='color:#ff7b72'>{prot}</span>" if rw
                         else f"<span style='color:#e3b341'>{prot}</span>")
            rows += (
                f"<tr>"
                f"<td class='mono' style='color:#79c0ff'>{e.get('pid','')}</td>"
                f"<td class='mono'>{_e(e.get('process',''))}</td>"
                f"<td class='mono' style='font-size:.78rem'>{_e(e.get('start_vpn',''))}</td>"
                f"<td>{prot_cell}</td>"
                f"<td class='mono' style='font-size:.75rem;max-width:280px;overflow:hidden;white-space:nowrap'>"
                f"{_e(e.get('disasm','')[:80])}</td>"
                f"</tr>"
            )
        note = (f"<p style='color:#484f58;font-size:.78rem'>(전체 {len(malfind)}건 중 50건 표시)</p>"
                if len(malfind) > 50 else "")
        parts.append(
            f"<div class='card' style='margin-bottom:1.2rem'>"
            f"<h4 style='color:#ff7b72;margin-top:0'>⚠ malfind — 주입 코드 탐지</h4>"
            f"<div style='overflow-x:auto'><table>"
            f"<tr><th>PID</th><th>프로세스</th><th>주소</th><th>보호 속성</th><th>디스어셈블</th></tr>"
            f"{rows}</table></div>{note}</div>"
        )

    # ── pstree (메모리 기준 프로세스 트리) ──────────────────────────
    if pstree:
        rows = ""
        for e in pstree[:40]:
            rows += (
                f"<tr>"
                f"<td class='mono' style='color:#79c0ff'>{e.get('pid','')}</td>"
                f"<td class='mono' style='color:#484f58'>{e.get('ppid','')}</td>"
                f"<td class='mono'>{_e(e.get('name',''))}</td>"
                f"<td class='mono' style='font-size:.78rem;color:#8b949e'>{_e(e.get('create_time',''))}</td>"
                f"<td class='mono' style='font-size:.75rem;max-width:260px;overflow:hidden;white-space:nowrap'>"
                f"{_e(e.get('cmd',''))}</td>"
                f"</tr>"
            )
        parts.append(
            f"<div class='card' style='margin-bottom:1.2rem'>"
            f"<h4 style='margin-top:0'>프로세스 트리 (메모리 기준)</h4>"
            f"<p style='color:#8b949e;font-size:.78rem'>DKOM으로 숨겨진 프로세스가 있으면 여기에 표시됩니다.</p>"
            f"<div style='overflow-x:auto'><table>"
            f"<tr><th>PID</th><th>PPID</th><th>이름</th><th>생성 시각</th><th>커맨드라인</th></tr>"
            f"{rows}</table></div></div>"
        )

    # ── netscan ───────────────────────────────────────────────────────
    if netscan:
        rows = ""
        for e in netscan[:40]:
            state = _e(e.get("state", ""))
            state_style = "color:#ff7b72" if state == "ESTABLISHED" else "color:#8b949e"
            rows += (
                f"<tr>"
                f"<td class='mono'>{_e(e.get('proto',''))}</td>"
                f"<td class='mono'>{_e(e.get('local',''))}</td>"
                f"<td class='mono' style='color:#e3b341'>{_e(e.get('foreign',''))}</td>"
                f"<td style='{state_style}'>{state}</td>"
                f"<td class='mono' style='color:#79c0ff'>{e.get('pid','')}</td>"
                f"<td class='mono'>{_e(e.get('owner',''))}</td>"
                f"</tr>"
            )
        parts.append(
            f"<div class='card' style='margin-bottom:1.2rem'>"
            f"<h4 style='margin-top:0'>네트워크 아티팩트 (메모리 기준)</h4>"
            f"<p style='color:#8b949e;font-size:.78rem'>이미 종료된 연결 포함 — tshark 누락분 보완</p>"
            f"<div style='overflow-x:auto'><table>"
            f"<tr><th>Proto</th><th>로컬</th><th>원격</th><th>상태</th><th>PID</th><th>프로세스</th></tr>"
            f"{rows}</table></div></div>"
        )

    # ── connscan ──────────────────────────────────────────────────────
    if connscan:
        rows = ""
        for e in connscan[:40]:
            state = _e(e.get("state", ""))
            state_style = "color:#ff7b72" if state == "ESTABLISHED" else "color:#8b949e"
            rows += (
                f"<tr>"
                f"<td class='mono'>{_e(e.get('proto',''))}</td>"
                f"<td class='mono'>{_e(e.get('local',''))}</td>"
                f"<td class='mono' style='color:#e3b341'>{_e(e.get('foreign',''))}</td>"
                f"<td style='{state_style}'>{state or '(종료)'}</td>"
                f"<td class='mono' style='color:#79c0ff'>{e.get('pid','')}</td>"
                f"<td class='mono'>{_e(e.get('owner',''))}</td>"
                f"</tr>"
            )
        parts.append(
            f"<div class='card' style='margin-bottom:1.2rem'>"
            f"<h4 style='margin-top:0'>연결 이력 (connscan — 종료 소켓 포함)</h4>"
            f"<p style='color:#8b949e;font-size:.78rem'>"
            f"pool-tag 스캔으로 이미 닫힌 TCP 소켓 구조체까지 복원 — netscan 누락분 보완</p>"
            f"<div style='overflow-x:auto'><table>"
            f"<tr><th>Proto</th><th>로컬</th><th>원격</th><th>상태</th><th>PID</th><th>프로세스</th></tr>"
            f"{rows}</table></div></div>"
        )

    # ── psxview ───────────────────────────────────────────────────────
    if psxview:
        hidden_entries = [e for e in psxview if e.get("hidden")]
        rows = ""
        for e in psxview[:60]:
            is_hidden = e.get("hidden", False)
            row_style = "background:#3d1f1f" if is_hidden else ""
            rows += (
                f"<tr style='{row_style}'>"
                f"<td class='mono' style='color:#79c0ff'>{e.get('pid','')}</td>"
                f"<td class='mono'>{_e(e.get('name',''))}</td>"
                f"<td style='text-align:center'>"
                f"{'<span style=\"color:#ff7b72\">✗</span>' if not e.get('pslist') else '<span style=\"color:#3fb950\">✓</span>'}"
                f"</td>"
                f"<td style='text-align:center'>"
                f"{'<span style=\"color:#3fb950\">✓</span>' if e.get('psscan') else '<span style=\"color:#484f58\">✗</span>'}"
                f"</td>"
                f"<td style='text-align:center'>"
                f"{'<span style=\"color:#3fb950\">✓</span>' if e.get('csrss') else '<span style=\"color:#484f58\">✗</span>'}"
                f"</td>"
                f"<td style='color:{'#ff7b72' if is_hidden else '#8b949e'};font-weight:{'bold' if is_hidden else 'normal'}'>"
                f"{'⚠ 은닉 의심' if is_hidden else '-'}</td>"
                f"</tr>"
            )
        hidden_count = len(hidden_entries)
        hdr_color = "#ff7b72" if hidden_count else "inherit"
        hdr_badge = (f" — <strong>{hidden_count}개 은닉 의심</strong>"
                     if hidden_count else "")
        parts.append(
            f"<div class='card' style='margin-bottom:1.2rem'>"
            f"<h4 style='margin-top:0;color:{hdr_color}'>프로세스 은닉 탐지 (psxview){hdr_badge}</h4>"
            f"<p style='color:#8b949e;font-size:.78rem'>"
            f"EPROCESS 목록(pslist)과 pool-tag 스캔(psscan)·CSRSS 목록 교차 비교 — "
            f"pslist에 없지만 psscan에서 발견되면 루트킷 은닉 의심</p>"
            f"<div style='overflow-x:auto'><table>"
            f"<tr><th>PID</th><th>프로세스</th><th>Pslist</th><th>Psscan</th><th>Csrss</th><th>판정</th></tr>"
            f"{rows}</table></div></div>"
        )

    # ── procdumps ─────────────────────────────────────────────────────
    if procdumps:
        def _sz(b):
            if not b: return ""
            if b < 1024 * 1024: return f"{b // 1024}KB"
            return f"{b // (1024 * 1024)}MB"

        rows = "".join(
            f"<tr>"
            f"<td class='mono' style='color:#79c0ff'>{e.get('pid','')}</td>"
            f"<td class='mono'>{_e(e.get('name',''))}</td>"
            f"<td class='mono' style='font-size:.75rem;color:#e3b341'>{_e(e.get('reason',''))}</td>"
            f"<td class='mono' style='font-size:.75rem;word-break:break-all'>{_e(e.get('dump_path',''))}</td>"
            f"<td class='mono' style='color:#8b949e'>{_sz(e.get('size',0))}</td>"
            f"</tr>"
            for e in procdumps
        )
        parts.append(
            f"<div class='card' style='margin-bottom:1.2rem'>"
            f"<h4 style='margin-top:0;color:#e3b341'>추출된 프로세스 PE ({len(procdumps)}개)</h4>"
            f"<p style='color:#8b949e;font-size:.78rem'>"
            f"malfind RWX 영역·psxview 은닉 프로세스에서 추출 — "
            f"VT 업로드·YARA 스캔·strings 분석 권장</p>"
            f"<div style='overflow-x:auto'><table>"
            f"<tr><th>PID</th><th>프로세스</th><th>추출 사유</th><th>파일 경로</th><th>크기</th></tr>"
            f"{rows}</table></div></div>"
        )

    # ── handles (Mutant) ─────────────────────────────────────────────
    mutants = [h for h in handles if h.get("type") == "Mutant"]
    if mutants:
        rows = "".join(
            f"<tr>"
            f"<td class='mono' style='color:#79c0ff'>{h.get('pid','')}</td>"
            f"<td class='mono'>{_e(h.get('name',''))}</td>"
            f"<td class='mono' style='color:#d2a8ff'>{_e(h.get('handle_name',''))}</td>"
            f"</tr>"
            for h in mutants[:30]
        )
        parts.append(
            f"<div class='card' style='margin-bottom:1.2rem'>"
            f"<h4 style='margin-top:0'>뮤텍스 (Mutant) 핸들</h4>"
            f"<p style='color:#8b949e;font-size:.78rem'>악성코드 패밀리 식별에 핵심 — "
            f"알려진 뮤텍스 이름으로 VT/MISP 검색 권장</p>"
            f"<div style='overflow-x:auto'><table>"
            f"<tr><th>PID</th><th>프로세스</th><th>뮤텍스 이름</th></tr>"
            f"{rows}</table></div></div>"
        )

    # ── cmdline (비교용) ──────────────────────────────────────────────
    if cmdline:
        rows = "".join(
            f"<tr>"
            f"<td class='mono' style='color:#79c0ff'>{c.get('pid','')}</td>"
            f"<td class='mono'>{_e(c.get('name',''))}</td>"
            f"<td class='mono' style='font-size:.78rem'>{_e(c.get('args',''))}</td>"
            f"</tr>"
            for c in cmdline[:20]
        )
        parts.append(
            f"<div class='card' style='margin-bottom:1.2rem'>"
            f"<h4 style='margin-top:0'>커맨드라인 (메모리 기준)</h4>"
            f"<p style='color:#8b949e;font-size:.78rem'>프로세스 홀로잉 탐지 — "
            f"원본 EXE와 다른 커맨드라인은 위장 징후</p>"
            f"<div style='overflow-x:auto'><table>"
            f"<tr><th>PID</th><th>프로세스</th><th>커맨드라인</th></tr>"
            f"{rows}</table></div></div>"
        )

    parts.append("</div>")
    return "\n".join(parts)


# ══════════════════════════════════════════════════════════════════════
# AI 분석 탭 렌더링
# ══════════════════════════════════════════════════════════════════════

def _md_to_html(text: str) -> str:
    """마크다운 → HTML 최소 변환 (헤딩·굵게·목록·코드·단락)."""
    import re
    lines = text.split("\n")
    out: list[str] = []
    in_ul = False
    in_code = False

    for line in lines:
        # 펜스 코드 블록
        if line.strip().startswith("```"):
            if in_ul:
                out.append("</ul>")
                in_ul = False
            if in_code:
                out.append("</code></pre>")
                in_code = False
            else:
                out.append("<pre><code>")
                in_code = True
            continue
        if in_code:
            out.append(_e(line))
            continue

        # 헤딩
        h3 = re.match(r"^### (.+)", line)
        h2 = re.match(r"^## (.+)", line)
        h1 = re.match(r"^# (.+)", line)
        if h1:
            if in_ul: out.append("</ul>"); in_ul = False
            out.append(f"<h2 style='color:#58a6ff;margin-top:1.8rem'>{_e(h1.group(1))}</h2>")
            continue
        if h2:
            if in_ul: out.append("</ul>"); in_ul = False
            out.append(f"<h3 style='color:#79c0ff;margin-top:1.4rem'>{_e(h2.group(1))}</h3>")
            continue
        if h3:
            if in_ul: out.append("</ul>"); in_ul = False
            out.append(f"<h4 style='color:#d2a8ff;margin-top:1rem'>{_e(h3.group(1))}</h4>")
            continue

        # 목록
        li = re.match(r"^[-*•]\s+(.+)", line)
        num = re.match(r"^\d+\.\s+(.+)", line)
        if li or num:
            item_text = (li or num).group(1)
            item_text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>",
                               _e(item_text))
            if not in_ul:
                out.append("<ul style='padding-left:1.4rem;margin:.3rem 0'>")
                in_ul = True
            out.append(f"<li style='margin:.18rem 0'>{item_text}</li>")
            continue

        if in_ul:
            out.append("</ul>")
            in_ul = False

        # 구분선
        if re.match(r"^---+$", line.strip()):
            out.append("<hr style='border-color:#30363d;margin:1rem 0'>")
            continue

        # 빈 줄
        if not line.strip():
            out.append("<p style='margin:.25rem 0'></p>")
            continue

        # 일반 텍스트 (굵게·코드 인라인)
        rendered = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", _e(line))
        rendered = re.sub(r"`(.+?)`",
                          r"<code style='background:#0d1117;padding:.1rem .3rem;"
                          r"border-radius:3px;font-size:.8rem'>\1</code>",
                          rendered)
        out.append(f"<p style='margin:.25rem 0;line-height:1.7'>{rendered}</p>")

    if in_ul:
        out.append("</ul>")
    if in_code:
        out.append("</code></pre>")

    return "\n".join(out)


def _parse_ai_sections(text: str) -> dict:
    """any.run 포맷 텍스트 → 섹션별 dict 파싱."""
    import re as _re

    SECTION_TITLES = [
        "분석 분류", "핵심 요약", "실행 흐름", "행위 분석", "결론",
        # 영문 fallback (모델이 영문으로 출력한 경우)
        "Analytical classification", "Executive summary",
        "Execution flow", "Behavioral analysis", "Conclusion",
    ]
    KO_MAP = {
        "Analytical classification": "분석 분류",
        "Executive summary": "핵심 요약",
        "Execution flow": "실행 흐름",
        "Behavioral analysis": "행위 분석",
        "Conclusion": "결론",
    }

    # 섹션 경계 탐지
    pattern = "|".join(_re.escape(t) for t in SECTION_TITLES)
    splits = list(_re.finditer(rf"^({pattern})\s*$", text, _re.MULTILINE))

    sections: dict[str, str] = {}
    for i, m in enumerate(splits):
        title = KO_MAP.get(m.group(1), m.group(1))
        end   = splits[i + 1].start() if i + 1 < len(splits) else len(text)
        body  = text[m.end():end].strip()
        sections[title] = body

    return sections


def _render_classification(body: str) -> str:
    """분석 분류 섹션 → 카드 HTML."""
    import re as _re

    def _field(label: str) -> str:
        m = _re.search(rf"^{_re.escape(label)}:\s*(.+)", body, _re.MULTILINE)
        return m.group(1).strip() if m else ""

    threat   = _field("위협 수준") or _field("Threat level")
    obj      = _field("주요 분석 대상") or _field("Main analyzed object")
    desc     = _field("설명") or _field("Description")

    # 위협 수준 색상
    tl = threat.lower()
    if "악성" in tl or "malicious" in tl:
        threat_color = "#ff7b72"; threat_bg = "rgba(255,123,114,.12)"
    elif "의심" in tl or "suspicious" in tl:
        threat_color = "#ffa657"; threat_bg = "rgba(255,166,87,.12)"
    else:
        threat_color = "#56d364"; threat_bg = "rgba(86,211,100,.10)"

    # 태그 파싱 (태그 및 해석 블록)
    # 태그 블록이 섹션 끝에 있어도 캡처되도록 lookahead에 $ 별도 처리
    tag_block_m = _re.search(
        r"(?:태그 및 해석|Tags & interpretation)[:\s]*\n([\s\S]+?)(?=\n(?:위협|주요|설명)|$)",
        body, _re.IGNORECASE,
    )
    tag_html = ""
    if tag_block_m:
        tag_lines = tag_block_m.group(1).strip().splitlines()
        chips = []
        for tl_line in tag_lines:
            tl_line = tl_line.strip().lstrip("-•").strip()
            if not tl_line:
                continue
            # "[tag]: 설명" 또는 "tag: 설명" 형태 모두 처리
            tm = _re.match(r"^\[?([a-zA-Z가-힣/_\-]+)\]?:\s*(.+)", tl_line)
            if tm:
                chip_label = _e(tm.group(1).strip())
                chip_title = _e(tm.group(2).strip())
                chips.append(
                    f"<span title='{chip_title}' style='display:inline-block;"
                    f"background:#1f2d3d;border:1px solid #30363d;border-radius:12px;"
                    f"padding:2px 10px;font-size:.75rem;color:#79c0ff;margin:2px 3px 2px 0;"
                    f"cursor:help'>{chip_label}</span>"
                )
        if chips:
            tag_html = (
                "<div style='margin-top:.6rem'>"
                "<span style='font-size:.75rem;color:#8b949e;margin-right:.4rem'>태그</span>"
                + "".join(chips) + "</div>"
            )

    return (
        f"<div class='card' style='margin-bottom:1rem'>"
        f"<div style='display:flex;align-items:center;gap:.6rem;margin-bottom:.7rem'>"
        f"<span style='background:{threat_bg};color:{threat_color};border:1px solid {threat_color};"
        f"border-radius:4px;padding:3px 10px;font-size:.82rem;font-weight:600'>{_e(threat)}</span>"
        f"<span style='color:#8b949e;font-size:.8rem'>위협 수준</span>"
        f"</div>"
        f"<table class='kv' style='margin-bottom:.4rem'>"
        f"<tr><td style='width:130px;color:#8b949e'>주요 분석 대상</td>"
        f"<td class='mono' style='font-size:.85rem'>{_e(obj)}</td></tr>"
        f"<tr><td style='color:#8b949e'>설명</td>"
        f"<td style='font-size:.85rem;line-height:1.6'>{_e(desc)}</td></tr>"
        f"</table>"
        f"{tag_html}"
        f"</div>"
    )


def _render_summary(body: str) -> str:
    return (
        f"<div class='card' style='margin-bottom:1rem'>"
        f"<p style='margin:0;line-height:1.8;font-size:.88rem'>{_e(body).replace(chr(10), '<br>')}</p>"
        f"</div>"
    )


def _render_exec_flow(body: str) -> str:
    import re as _re

    LABEL_STYLES = {
        "사용자 행위":  ("#79c0ff", "#1a2d3d"),
        "User-driven":  ("#79c0ff", "#1a2d3d"),
        "준비 단계":    ("#ffa657", "#2d1f0a"),
        "Preparatory":  ("#ffa657", "#2d1f0a"),
        "자율 실행":    ("#ff7b72", "#2d1117"),
        "Autonomous":   ("#ff7b72", "#2d1117"),
    }
    DEFAULT_STYLE = ("#8b949e", "#161b22")

    rows = []
    for line in body.splitlines():
        line = line.strip().lstrip("-•").strip()
        if not line:
            continue
        m = _re.match(r"\[([^\]]+)\]\s*(.*)", line)
        if m:
            lbl   = m.group(1).strip()
            desc  = m.group(2).strip()
            color, bg = LABEL_STYLES.get(lbl, DEFAULT_STYLE)
            rows.append(
                f"<div style='display:flex;align-items:flex-start;gap:.6rem;"
                f"padding:.45rem 0;border-bottom:1px solid #21262d'>"
                f"<span style='flex-shrink:0;background:{bg};color:{color};"
                f"border:1px solid {color};border-radius:4px;padding:1px 8px;"
                f"font-size:.72rem;font-weight:600;margin-top:2px'>[{_e(lbl)}]</span>"
                f"<span style='font-size:.85rem;line-height:1.6'>{_e(desc)}</span>"
                f"</div>"
            )
        else:
            rows.append(
                f"<div style='padding:.4rem 0;border-bottom:1px solid #21262d;"
                f"font-size:.85rem;color:#c9d1d9'>{_e(line)}</div>"
            )

    if not rows:
        return ""
    return (
        "<div class='card' style='margin-bottom:1rem'>"
        + "".join(rows)
        + "</div>"
    )


def _render_behavioral(body: str) -> str:
    import re as _re

    FIELDS = [
        ("로더 / 스테이징",                    "Loader / Staging"),
        ("실행 및 피벗 (LOLBin / 인터프리터)",  "Execution & Pivots"),
        ("지속성 (관찰된 경우)",                "Persistence"),
        ("탐색 / 수집 (관찰된 경우)",           "Discovery / Collection"),
        ("네트워크 / C2 또는 유출 (관찰된 경우)","Network / C2"),
        ("오류 / 크래시 (관찰된 경우)",          "Errors / Crashes"),
    ]

    rows = []
    for ko_label, en_label in FIELDS:
        # 한/영 모두 시도
        for label in (ko_label, en_label):
            m = _re.search(
                rf"^{_re.escape(label)}[^:\n]*:\s*(.+?)(?=\n[^\s]|$)",
                body, _re.MULTILINE | _re.DOTALL,
            )
            if m:
                val = m.group(1).strip()
                break
        else:
            val = "관찰되지 않음"

        absent = val in ("관찰되지 않음", "관찰 안됨", "없음", "Not observed", "활동 없음")
        val_style = "color:#6e7681;font-style:italic" if absent else "color:#c9d1d9"
        rows.append(
            f"<tr>"
            f"<td style='color:#8b949e;font-size:.8rem;width:220px;"
            f"padding:.45rem .6rem;vertical-align:top;white-space:nowrap'>{_e(ko_label)}</td>"
            f"<td style='{val_style};font-size:.85rem;padding:.45rem .6rem;"
            f"line-height:1.6'>{_e(val)}</td>"
            f"</tr>"
        )

    return (
        "<div class='card' style='margin-bottom:1rem'>"
        "<table style='width:100%;border-collapse:collapse'>"
        + "".join(rows)
        + "</table></div>"
    )


def _render_conclusion(body: str) -> str:
    return (
        f"<div class='card' style='margin-bottom:1rem;border-left:3px solid #58a6ff;"
        f"padding-left:1rem'>"
        f"<p style='margin:0;line-height:1.8;font-size:.88rem'>{_e(body).replace(chr(10), '<br>')}</p>"
        f"</div>"
    )


def _ai_html(result) -> str:
    """AI 분석 결과 탭 렌더링 (any.run 스타일)."""
    ai = getattr(result, "ai_analysis", None) or {}
    model     = ai.get("model", "")
    response  = ai.get("response", "")
    elapsed   = ai.get("elapsed_sec", 0)
    prompt_ch = ai.get("prompt_chars", 0)
    error     = ai.get("error", "")

    parts = ["<h2>🤖 AI 위협 분석</h2>"]

    # 메타
    parts.append(
        f"<p style='color:#8b949e;font-size:.8rem;margin-bottom:1.2rem'>"
        f"모델: <code>{_e(model)}</code> &nbsp;|&nbsp; "
        f"응답 시간: {elapsed}s &nbsp;|&nbsp; 입력: {prompt_ch:,}자"
        f"</p>"
    )

    if not ai:
        parts.append(
            "<div class='alert alert-info'>"
            "AI 분석 결과가 없습니다. Ollama가 실행 중이면 자동으로 분석됩니다.<br>"
            "<code>ollama serve</code> 실행 후 재분석하거나 "
            "<code>ollama pull qwen2.5:7b</code>로 모델을 먼저 설치하세요."
            "</div>"
        )
        return "\n".join(parts)

    if error:
        parts.append(
            f"<div class='alert alert-warning'>"
            f"<strong>AI 분석 오류</strong><br>{_e(error)}<br><br>"
            f"1. <code>ollama serve</code> 실행 확인<br>"
            f"2. <code>ollama pull {_e(model)}</code> 로 모델 다운로드<br>"
            f"3. <code>--no-ai</code> 옵션으로 비활성화 가능"
            f"</div>"
        )
        if not response.strip():
            return "\n".join(parts)

    if not response.strip():
        parts.append("<div class='alert alert-warning'>AI 응답이 비어있습니다.</div>")
        return "\n".join(parts)

    # 섹션 파싱 → 카드 렌더링
    sections = _parse_ai_sections(response)

    SECTION_ORDER = [
        ("분석 분류",  _render_classification),
        ("핵심 요약",  _render_summary),
        ("실행 흐름",  _render_exec_flow),
        ("행위 분석",  _render_behavioral),
        ("결론",       _render_conclusion),
    ]

    rendered_any = False
    for title, renderer in SECTION_ORDER:
        body = sections.get(title, "")
        if not body:
            continue
        parts.append(
            f"<h3 style='color:#79c0ff;margin:1.4rem 0 .5rem;font-size:.95rem;"
            f"letter-spacing:.02em'>{_e(title)}</h3>"
        )
        parts.append(renderer(body))
        rendered_any = True

    # 구조 파싱 실패 시 기존 마크다운 렌더링으로 fallback
    if not rendered_any:
        parts.append(
            "<div class='card' style='line-height:1.75;font-size:.88rem'>"
            + _md_to_html(response)
            + "</div>"
        )

    # 원문 접기
    parts.append(
        f"<details style='margin-top:1rem'>"
        f"<summary style='cursor:pointer;color:#8b949e;font-size:.8rem'>"
        f"▶ 원문 (Ollama raw 응답)</summary>"
        f"<pre style='background:#0d1117;border:1px solid #30363d;border-radius:6px;"
        f"padding:1rem;margin-top:.5rem;font-size:.76rem;overflow-x:auto;"
        f"white-space:pre-wrap;color:#c9d1d9'>{_e(response)}</pre>"
        f"</details>"
    )

    return "\n".join(parts)
