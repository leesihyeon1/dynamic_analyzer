"""통합 행위 그래프 — 판정 · 탐지 근거 · 프로세스 실행 흐름 · 행위를 한 장의 그림으로.

Joe Sandbox Behavior Graph 방식이다. 판정 카드에서 샘플 프로세스로, 다시 자식 프로세스로
실행 흐름이 위에서 아래로 이어지고, 각 프로세스가 한 일(연결·드롭·레지스트리·사이드로딩·
주입 흔적)은 그 프로세스 노드에 라벨 붙은 간선으로 바로 매달린다. 행위를 따로 떼어
목록으로 보여주지 않는다.

    [판정 카드] ──┬──────────▶ 탐지 근거 · 출처 미확인 통신
         │ 실행
    [샘플 프로세스] ─┬─ 연결 ─▶ 93.184.216.34:443
         │           ├─ 드롭 ─▶ updater.exe
         │ 실행      └─ 레지스트리 ─▶ Run 키 updater
    [자식 프로세스] ──── …
         │
       ┌─┴──────────┐
    [손자]        [손자]

Joe 처럼 행위 노드를 아래로 넓게 펼치면 프로세스 서너 단계만 돼도 폭이 수천 px 가 되어
보고서 폭에 맞추면 글자를 읽을 수 없다. 그래서 행위는 프로세스 카드 오른쪽에 세로로
매달고, 실행 흐름만 아래로 내려 보낸다 — 한 단계 폭이 노드+행위 한 벌(약 570px)로 묶인다.

관측 집계는 capability_graph._collect 를 그대로 쓴다(같은 근거, 같은 색 기준).
레이아웃 계산(build_behavior_graph)과 그리기(behavior_graph_html)를 나눠 겹침을 테스트한다.
라이브러리 없이 인라인 SVG — 격리 VM 에서 오프라인으로 열려야 한다.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from html import escape
from pathlib import PureWindowsPath

from exporters.capability_graph import _ICON_COLOR, _ICONS, _LEVEL_NAME, _collect

C_MAL, C_SUS, C_OK, C_INFO, C_IDLE = "#ff6b6b", "#f0b429", "#3fb98f", "#4fb3d9", "#6b7f99"
_LEVEL_STROKE = {2: C_MAL, 1: C_SUS, 0: "#3b4d66", -1: "#3b4d66"}

_SIZE = {"root": (340, 150), "sig": (240, 50), "proc": (206, 96), "leaf": (240, 48), "more": (176, 38)}
_BRANCH = 92         # 노드 오른쪽 → 행위 노드 왼쪽 (간선 라벨 자리)
_SPINE = 20          # 노드 오른쪽 → 행위 간선의 세로 줄기
_COMB_GAP = 10       # 행위 노드 사이
_KID_GAP = 60        # 노드·행위 묶음 아래 → 자식 프로세스 줄 (간선 라벨 자리)
_SIB_GAP = 44        # 형제 프로세스 서브트리 사이
_FLOW_X = 103        # 실행 흐름 선의 x (노드 왼쪽 기준) — 프로세스 노드 가운데
_PAD = 24
_MAX_LEAVES = 5      # 프로세스당 그리는 행위 노드 (나머지는 '외 N개')
_MAX_SIGS = 3
_MAX_ROOT_NET = 3
_MAX_PROCS = 40

# 간선 라벨 — 짧게. 드롭은 따로 정한다(파일 쓰기 중 판정 근거가 있는 것).
_EDGE_LABEL = {"파일 쓰기": "쓰기", "값 설정": "레지스트리", "모듈 로드": "로드",
               "DLL 사이드로딩 후보": "사이드로딩", "메모리 스캔": "주입 흔적",
               "민감 경로 읽기": "민감 읽기", "자식 실행": "실행", "TCP 소켓": "연결",
               "UDP 소켓": "연결", "TCP 연결": "연결", "UDP 송신": "송신", "DNS 질의": "DNS",
               "DNS 질의 (응답 없음)": "DNS 무응답", "TLS ClientHello": "TLS",
               "화면 캡처": "화면 캡처", "키 입력 기록": "키 입력"}
# 한 프로세스 아래 행위 노드 순서 — 통신이 맨 앞(Joe 와 같다)
_KIND_ORDER = {"net": 0, "file": 1, "module": 2, "reg": 3, "proc": 4}


@dataclass
class GNode:
    id: str
    kind: str                 # root · sig · proc · leaf · more
    label: str
    sub: str = ""
    level: int = 0            # 2 악성 근거 · 1 의심 근거 · 0 일반 행위 · -1 행위 없음
    icon: str = ""            # _ICONS 키
    edge: str = ""            # 부모에서 들어오는 간선 라벨
    tip: str = ""             # 마우스오버 전체 텍스트
    pid: int | None = None    # 누르면 이동할 프로세스
    link: str = ""            # 'proc' · 'verdict' · ''
    attach: str = "comb"      # comb: 부모 오른쪽 행위 줄 · flow: 부모 아래 실행 흐름
    counts: dict = field(default_factory=dict)
    meta: dict = field(default_factory=dict)
    children: list = field(default_factory=list)
    w: float = 0
    h: float = 0
    left: float = 0
    top: float = 0

    @property
    def cy(self):
        return self.top + self.h / 2


def walk(node):
    yield node
    for c in node.children:
        yield from walk(c)


# ── 텍스트 폭 추정 (SVG 는 줄바꿈·자동 말줄임이 없다) ─────────────────────────
def _text_w(s: str, size: float) -> float:
    return sum(size * (1.0 if ord(ch) > 0x2E7F else 0.6) for ch in s)


def _fit(s, px: float, size: float = 12) -> str:
    s = str(s or "")
    if _text_w(s, size) <= px:
        return s
    out = ""
    for ch in s:
        if _text_w(out + ch + "…", size) > px:
            break
        out += ch
    return out + "…"


# ── 노드 구성 ────────────────────────────────────────────────────────────────
def _leaves(actions, skip_children=frozenset()):
    """(동작, 아이콘)별 대상 → 행위 노드 후보. 같은 대상은 동작이 달라도 한 노드로 합친다."""
    merged: dict = {}
    for (action, icon), targets in actions.items():
        for (target, _), (detail, count, level) in targets.items():
            if action == "자식 실행" and PureWindowsPath(str(target)).name.lower() in skip_children:
                continue      # 트리에 자식 프로세스 노드로 이미 그려진다
            key = (icon, str(target).lower())
            line = f"{action} · {detail}" if detail else action
            rec = merged.get(key)
            if rec is None:
                merged[key] = {"icon": icon, "target": str(target), "action": action,
                               "level": level, "count": count, "lines": [line]}
                continue
            rec["count"] += count
            if len(rec["lines"]) < 6:
                rec["lines"].append(line)
            if level > rec["level"]:
                rec["level"], rec["action"] = level, action
    return sorted(merged.values(), key=lambda r: (-r["level"], -r["count"], r["target"].lower()))


def _pick(items, limit=_MAX_LEAVES):
    """판정 근거가 있는 것부터. 근거가 하나도 없으면 관측 행위를 몇 개 보여준다."""
    shown = [r for r in items if r["level"] >= 1][:limit]
    if len(shown) < 3:
        shown += [r for r in items if r["level"] < 1][:3 - len(shown)]
    ids = {id(r) for r in shown}
    rest = [r for r in items if id(r) not in ids]
    shown.sort(key=lambda r: (_KIND_ORDER.get(r["icon"], 9), -r["level"]))
    return shown, rest


def _leaf_node(nid, r, pid, evidence):
    target, icon = r["target"], r["icon"]
    if icon == "net":
        label, sub = target, ""
    else:
        path = PureWindowsPath(target)
        label = path.name or target
        parts = path.parent.parts if path.name else ()
        sub = ("…\\" + "\\".join(parts[-2:])) if len(parts) > 2 else "\\".join(parts)
    if r["count"] > 1:
        sub = (sub + " · " if sub else "") + f"{r['count']:,}회"
    edge = _EDGE_LABEL.get(r["action"], r["action"])
    if r["action"] == "파일 쓰기" and r["level"] >= 1:
        edge = "드롭"
    tip = target + (f" — {_LEVEL_NAME[r['level']]}" if r["level"] in _LEVEL_NAME else "")
    if evidence:
        tip += "\n" + "\n".join(r["lines"])
    return GNode(nid, "leaf", label, sub, r["level"], icon, edge, tip, pid=pid,
                 link="proc" if pid is not None else "")


def _more_node(nid, rows, noun, *, pid=None, link="", edge=""):
    shown = rows[:20]
    tip = "\n".join(shown) + (f"\n… 외 {len(rows) - 20}개" if len(rows) > 20 else "")
    return GNode(nid, "more", f"외 {len(rows)}개 {noun}", "", 0, "", edge, tip, pid=pid, link=link)


def build_behavior_graph(result, fallback_pids=None, *, verdict=None, sample_name="",
                         include_evidence=True):
    """그래프 노드 트리를 만들고 배치한다 → (root, 폭, 높이)."""
    groups, procs, names, lineage, loader_pids = _collect(result, fallback_pids)
    if verdict is None:
        from exporters.report_visuals import report_verdict
        verdict = report_verdict(result)
    sample_pid = getattr(result, "sample_pid", None)
    counter = iter(range(1, 1_000_000))

    def nid():
        return f"bg{next(counter)}"

    # ── 판정 카드 ──
    cfg = getattr(result, "config", None)
    start = getattr(result, "start_time", 0) or 0
    when = datetime.fromtimestamp(start).strftime("%Y-%m-%d %H:%M") if start else "미확인"
    vlevel = verdict.get("level", "ok")
    root = GNode("bg0", "root", sample_name or "전체 시스템 모니터링",
                 level={"mal": 2, "sus": 1}.get(vlevel, 0))
    root.meta = {"verdict": vlevel, "rows": [
        ("샘플", sample_name or "전체 시스템 모니터링"),
        ("분석 시각", when),
        ("관찰 시간", f"{getattr(cfg, 'timeout', '?')}초"),
        ("위협 점수", f"{verdict.get('score', 0)} / 100"),
    ]}
    _fams = [f["name"] for f in ((getattr(result, "malware_traits", None) or {}).get("families") or [])
             if f.get("confidence") == "HIGH"]
    if _fams:
        root.meta["rows"].append(("패밀리", ", ".join(_fams)))

    # ── 어느 프로세스에도 귀속하지 못한 통신 (PCAP 에서만 보임) ──
    if None in groups:
        items = _leaves(groups[None])
        for r in items[:_MAX_ROOT_NET]:
            node = _leaf_node(nid(), r, None, include_evidence)
            node.edge = "출처 미확인"
            node.tip = "어느 프로세스의 통신인지 확인되지 않음 (패킷 캡처에서만 보임)\n" + node.tip
            root.children.append(node)
        rest = items[_MAX_ROOT_NET:]
        if rest:
            root.children.append(_more_node(nid(), [f"{r['action']} · {r['target']}" for r in rest],
                                            "통신", edge="출처 미확인"))

    # ── 탐지 근거 (판정 요약과 같은 지표) ──
    inds = [i for lv in ("mal", "sus") for i in verdict.get("indicators", []) if i["level"] == lv]
    for ind in inds[:_MAX_SIGS]:
        tip = (ind["title"] + (f"\n{ind['ev']}" if ind.get("ev") else "")
               + (f"\n{ind['tid']}" if ind.get("tid") else ""))
        root.children.append(GNode(nid(), "sig", ind["title"], ind.get("cat", ""),
                                   2 if ind["level"] == "mal" else 1, "", "", tip, link="verdict"))
    if len(inds) > _MAX_SIGS:
        root.children.append(_more_node(nid(), [i["title"] for i in inds[_MAX_SIGS:]],
                                        "탐지 근거", link="verdict"))

    # ── 프로세스 실행 흐름 ──
    cand = set(lineage) | {p for p in groups if p is not None}

    def ppid_of(pid):
        return getattr(procs.get(pid), "ppid", None)

    kids = defaultdict(list)
    for pid in cand:
        pp = ppid_of(pid)
        if pp in cand and pp != pid:
            kids[pp].append(pid)

    keep_memo: dict = {}

    def keep(pid, stack=()):
        """샘플이거나, 행위가 있거나, 행위 있는 자손이 있으면 그린다."""
        if pid in keep_memo:
            return keep_memo[pid]
        if pid in stack:
            return False
        r = (pid == sample_pid or pid in groups
             or any(keep(c, stack + (pid,)) for c in kids.get(pid, ())))
        keep_memo[pid] = r
        return r

    visited: set = set()

    def proc_name(pid):
        return names.get(pid) or getattr(procs.get(pid), "name", "") or "이름 미확인"

    def proc_node(pid, edge):
        visited.add(pid)
        p = procs.get(pid)
        roles = (["샘플"] if pid == sample_pid else []) + (["로더"] if pid in loader_pids else [])
        actions = groups.get(pid, {})
        level = max((rec[2] for targets in actions.values() for rec in targets.values()), default=-1)
        counts: dict = defaultdict(int)
        for (_action, icon), targets in actions.items():
            if icon != "proc":
                counts[icon] += len(targets)
        cmd = getattr(p, "cmdline", "") or ""
        cmd = cmd if isinstance(cmd, str) else " ".join(cmd)
        exe = getattr(p, "exe", "") or ""
        tip = (f"{proc_name(pid)} (PID {pid})" + (f"\n{exe}" if exe else "")
               + (f"\n{cmd}" if cmd and include_evidence else ""))
        node = GNode(nid(), "proc", proc_name(pid), f"PID {pid}" + "".join(" · " + r for r in roles),
                     level, "proc", edge, tip, pid=pid, link="proc", attach="flow", counts=dict(counts))

        child_pids = [c for c in sorted(kids.get(pid, ())) if c not in visited]
        shown_kids = [c for c in child_pids if keep(c)]
        hidden_kids = [c for c in child_pids if not keep(c)]
        child_names = frozenset(proc_name(c).lower() for c in child_pids)
        shown, rest = _pick(_leaves(actions, skip_children=child_names))
        node.children += [_leaf_node(nid(), r, pid, include_evidence) for r in shown]
        if rest:
            node.children.append(_more_node(nid(), [f"{r['action']} · {r['target']}" for r in rest],
                                            "행위", pid=pid, link="proc"))
        for c in shown_kids:
            if len(visited) >= _MAX_PROCS:
                hidden_kids.append(c)
                continue
            node.children.append(proc_node(c, "실행"))
        if hidden_kids:
            more = _more_node(nid(), [f"{proc_name(c)} (PID {c})" for c in hidden_kids],
                              "프로세스", pid=pid, link="proc", edge="실행")
            more.attach = "flow"
            node.children.append(more)
        return node

    roots = sorted((p for p in cand if ppid_of(p) not in cand or ppid_of(p) == p),
                   key=lambda p: (p != sample_pid, p))
    for pid in roots:
        if keep(pid) and pid not in visited and len(visited) < _MAX_PROCS:
            root.children.append(proc_node(pid, "실행"))
    # 부모 고리(PID 재사용) 때문에 루트에서 닿지 않은 행위 프로세스도 빠뜨리지 않는다
    for pid in sorted(p for p in groups if p is not None and p not in visited):
        if len(visited) < _MAX_PROCS:
            root.children.append(proc_node(pid, "실행"))

    width, height = _layout(root)
    return root, width, height


# ── 배치 ─────────────────────────────────────────────────────────────────────
def _move(node, dx, dy):
    for n in walk(node):
        n.left += dx
        n.top += dy


def _layout_sub(n):
    """n 서브트리를 (0,0) 기준으로 배치하고 (폭, 높이)를 돌려준다.

    머리 = 노드 + 오른쪽에 세로로 매단 행위 노드. 자식 프로세스 서브트리는 머리 아래 한 줄에
    왼쪽부터 나란히 놓는다 — 자식이 하나면 부모와 같은 x 라 실행 흐름이 곧은 세로선이 된다.
    """
    n.w, n.h = _SIZE[n.kind]
    if n.kind == "root":
        n.h += 22 * max(0, len(n.meta.get("rows", ())) - 4)
    n.left = n.top = 0
    comb = [c for c in n.children if c.attach == "comb"]
    kids = [c for c in n.children if c.attach == "flow"]
    width, head_h = n.w, n.h
    if comb:
        y, x = 0.0, n.w + _BRANCH
        for c in comb:
            c.w, c.h = _SIZE[c.kind]
            c.left, c.top = x, y
            y += c.h + _COMB_GAP
        comb_h = y - _COMB_GAP
        if comb_h < n.h:                     # 행위가 노드보다 짧으면 노드 가운데에 맞춘다
            for c in comb:
                c.top += (n.h - comb_h) / 2
        width = x + max(c.w for c in comb)
        head_h = max(n.h, comb_h)
    height = head_h
    if kids:
        x, row_top, row_h = 0.0, head_h + _KID_GAP, 0.0
        for k in kids:
            kw, kh = _layout_sub(k)
            _move(k, x, row_top)
            x += kw + _SIB_GAP
            row_h = max(row_h, kh)
        width = max(width, x - _SIB_GAP)
        height = row_top + row_h
    return width, height


def _layout(root):
    width, height = _layout_sub(root)
    _move(root, _PAD, _PAD)
    return width + 2 * _PAD, height + 2 * _PAD


def _flow_x(n):
    return n.left + (_FLOW_X if n.kind in ("root", "proc") else n.w / 2)


# ── 그리기 ───────────────────────────────────────────────────────────────────
def _svg_icon(kind, x, y, scale=0.75, color=None):
    return (f"<g transform='translate({x:.1f} {y:.1f}) scale({scale})' color='{color or _ICON_COLOR[kind]}'>"
            f"<path d='{_ICONS[kind]}' fill='none' stroke='currentColor' stroke-width='1.8' "
            "stroke-linecap='round' stroke-linejoin='round'/></g>")


def _attrs(n):
    """누를 수 있는 노드의 공통 속성."""
    if n.link == "proc" and n.pid is not None:
        act = f"bgGo({int(n.pid)})"
    elif n.link == "verdict":
        act = "bgGoVerdict()"
    else:
        return f" class='bg-node bg-{n.kind}'"
    return (f" class='bg-node bg-{n.kind} bg-link' tabindex='0' role='link' onclick='{act}'"
            " onkeydown='if(event.key===\"Enter\")this.onclick()'")


def _draw_root(n):
    v = n.meta["verdict"]
    color = {"mal": C_MAL, "sus": C_SUS}.get(v, C_OK)
    out = [f"<rect width='{n.w}' height='{n.h}' rx='12' fill='#16243a' stroke='{color}' stroke-width='1.6'/>",
           "<text x='18' y='28' class='bg-title'>행위 그래프</text>"]
    for i, (k, val) in enumerate(n.meta["rows"]):
        y = 56 + i * 22
        out.append(f"<text x='18' y='{y}' class='bg-k'>{escape(k)}</text>"
                   f"<text x='86' y='{y}' class='bg-v'>{escape(_fit(val, 140, 12))}</text>")
    for i, (key, text, c) in enumerate((("mal", "악성", C_MAL), ("sus", "의심", C_SUS),
                                        ("ok", "위협 미확인", C_OK))):
        y, on = 20 + i * 32, key == v
        out.append(f"<rect x='{n.w - 106}' y='{y}' width='88' height='26' rx='5' "
                   f"fill='{c if on else '#22324a'}'/>"
                   f"<text x='{n.w - 62}' y='{y + 17.5}' text-anchor='middle' class='bg-step{' on' if on else ''}'>"
                   f"{text}</text>")
    return out


def _draw_sig(n):
    fill, sub = ("#7a1f22", "#f5c9c9") if n.level == 2 else ("#5c4510", "#f3dfa5")
    return [f"<rect width='{n.w}' height='{n.h}' rx='10' fill='{fill}' stroke='{_LEVEL_STROKE[n.level]}' stroke-width='1.4'/>",
            f"<text x='{n.w / 2}' y='22' text-anchor='middle' class='bg-sig'>{escape(_fit(n.label, n.w - 20, 12.5))}</text>",
            f"<text x='{n.w / 2}' y='40' text-anchor='middle' class='bg-sub' style='fill:{sub}'>"
            f"{escape(_fit(n.sub, n.w - 20, 11))}</text>"]


def _draw_more(n):
    return [f"<rect width='{n.w}' height='{n.h}' rx='10' fill='#1a2638' stroke='{C_IDLE}' stroke-dasharray='5 4'/>",
            f"<text x='{n.w / 2}' y='{n.h / 2 + 4.5}' text-anchor='middle' class='bg-more'>"
            f"{escape(_fit(n.label, n.w - 16, 12))}</text>"]


def _draw_proc(n):
    out = [f"<rect width='{n.w}' height='{n.h}' rx='12' fill='#13233a' stroke='{C_INFO}' stroke-width='1.6'/>",
           _svg_icon("proc", 12, 12, 0.8),
           f"<text x='42' y='26' class='bg-name'>{escape(_fit(n.label, n.w - 54, 13.5))}</text>",
           f"<text x='42' y='43' class='bg-sub'>{escape(_fit(n.sub, n.w - 54, 11))}</text>"]
    # 판정 막대 — 악성 근거 · 의심 근거 · 일반 행위 · 행위 없음 중 하나가 켜진다
    seg_w = (n.w - 28 - 3 * 4) / 4
    active = {2: 0, 1: 1, 0: 2}.get(n.level, 3)
    for i, c in enumerate((C_MAL, C_SUS, C_OK, C_IDLE)):
        out.append(f"<rect x='{14 + i * (seg_w + 4):.1f}' y='54' width='{seg_w:.1f}' height='8' rx='4' "
                   f"fill='{c if i == active else '#2a3b54'}'/>")
    x = 14
    for kind in ("net", "file", "reg", "module"):
        cnt = n.counts.get(kind)
        if not cnt:
            continue
        out.append(_svg_icon(kind, x, 70, 0.6) + f"<text x='{x + 18}' y='83' class='bg-cnt'>{cnt:,}</text>")
        x += 22 + _text_w(f"{cnt:,}", 11) + 10
    return out


def _draw_leaf(n):
    out = [f"<rect width='{n.w}' height='{n.h}' rx='9' fill='#172539' stroke='{_LEVEL_STROKE[n.level]}' "
           f"stroke-width='{1.6 if n.level > 0 else 1}'/>",
           _svg_icon(n.icon or "file", 11, n.h / 2 - 9, 0.75)]
    right = 30 if n.level == 2 else 12
    label_y = 22 if n.sub else n.h / 2 + 4.5
    weight = " bg-strong" if n.level > 0 else ""
    out.append(f"<text x='38' y='{label_y}' class='bg-leaf{weight}'>"
               f"{escape(_fit(n.label, n.w - 38 - right, 12.5))}</text>")
    if n.sub:
        out.append(f"<text x='38' y='39' class='bg-sub'>{escape(_fit(n.sub, n.w - 38 - right, 10.5))}</text>")
    if n.level == 2:     # 악성 근거 표식
        out.append(f"<circle cx='{n.w - 16}' cy='{n.h / 2}' r='8.5' fill='{C_MAL}'/>"
                   f"<text x='{n.w - 16}' y='{n.h / 2 + 4.5}' text-anchor='middle' class='bg-haz'>!</text>")
    return out


_DRAW = {"root": _draw_root, "sig": _draw_sig, "more": _draw_more, "proc": _draw_proc, "leaf": _draw_leaf}


def _draw_edge(p, c):
    if c.attach == "flow":
        # 실행 흐름: 부모 아래 → (형제 공용 가로줄) → 자식 위. 자식이 같은 x 면 곧은 세로선
        x1, y1, x2, y2 = _flow_x(p), p.top + p.h, _flow_x(c), c.top
        if abs(x1 - x2) < 0.5:
            d = f"M{x1:.1f} {y1:.1f}V{y2 - 2:.1f}"
        else:
            bus = y2 - _KID_GAP / 2
            d = f"M{x1:.1f} {y1:.1f}V{bus:.1f}H{x2:.1f}V{y2 - 2:.1f}"
        path = f"<path d='{d}' class='bg-edge bg-flow' marker-end='url(#bg-arrow)'/>"
        label = (f"<text x='{x2 + 8:.1f}' y='{y2 - 9:.1f}' class='bg-elabel'>{escape(c.edge)}</text>"
                 if c.edge else "")
        return path + label
    # 행위: 노드 오른쪽 → 세로 줄기 → 행위 노드 왼쪽. 노드 높이 안이면 곧은 가로선
    x1, spine, x2, y2 = p.left + p.w, p.left + p.w + _SPINE, c.left, c.cy
    if p.top + 14 <= y2 <= p.top + p.h - 14:
        d = f"M{x1:.1f} {y2:.1f}H{x2 - 2:.1f}"
    else:
        y1 = min(max(y2, p.top + 14), p.top + p.h - 14)
        d = f"M{x1:.1f} {y1:.1f}H{spine:.1f}V{y2:.1f}H{x2 - 2:.1f}"
    path = f"<path d='{d}' class='bg-edge' marker-end='url(#bg-arrow)'/>"
    if not c.edge:
        return path
    return path + (f"<text x='{(spine + x2) / 2:.1f}' y='{y2 - 6:.1f}' text-anchor='middle' class='bg-elabel'>"
                   f"{escape(_fit(c.edge, x2 - spine - 8, 11))}</text>")


_CSS = """<style>
.bg{margin:4px 0 30px}
.bg-bar{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px 16px;padding:0 0 10px}
.bg-legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:.76rem;color:var(--muted,#a7b9c9)}
.bg-legend span:before{content:'';display:inline-block;width:10px;height:10px;border-radius:2px;
  background:var(--c);margin-right:6px;vertical-align:-1px}
.bg-zoom{display:flex;gap:4px}
.bg-zoom button{background:#16243a;border:1px solid #344256;color:#cfe0f3;font-size:.78rem;padding:3px 10px;
  border-radius:6px;cursor:pointer}
.bg-zoom button:hover,.bg-zoom button:focus-visible{border-color:var(--accent,#45d6bf)}
.bg-view{overflow:auto;border:1px solid #2a3b54;border-radius:10px;cursor:grab;
  background:#0d1726 radial-gradient(#24354f 1px,transparent 1.4px) 0 0/18px 18px;touch-action:none}
.bg-view.drag{cursor:grabbing;user-select:none}
.bg-view svg{display:block;margin:0 auto}
.bg svg text{font-family:'Segoe UI','Malgun Gothic',sans-serif;fill:#e3ecf6}
.bg .bg-title{font-size:15px;font-weight:700}
.bg .bg-k{font-size:12px;fill:#8fa3bd}
.bg .bg-v{font-size:12px}
.bg .bg-step{font-size:11.5px;fill:#6b7f99;font-weight:600}
.bg .bg-step.on{fill:#0d1726;font-weight:800}
.bg .bg-sig{font-size:12.5px;font-weight:650;fill:#fff}
.bg .bg-sub{font-size:11px;fill:#8fa3bd}
.bg .bg-more{font-size:12px;fill:#a7b9c9}
.bg .bg-name{font-size:13.5px;font-weight:700}
.bg .bg-cnt{font-size:11px;fill:#c8d6ea}
.bg .bg-leaf{font-size:12.5px}
.bg .bg-leaf.bg-strong{font-weight:650}
.bg .bg-haz{font-size:12px;font-weight:800;fill:#0d1726}
.bg .bg-edge{fill:none;stroke:#5c7290;stroke-width:1.3}
.bg .bg-flow{stroke:#7f9cc0;stroke-width:2}
.bg .bg-elabel{font-size:11px;fill:#a7b9c9;paint-order:stroke;stroke:#0d1726;stroke-width:4px;stroke-linejoin:round}
.bg .bg-link{cursor:pointer;outline:none}
.bg .bg-link:hover>rect:first-of-type,.bg .bg-link:focus-visible>rect:first-of-type{stroke:#45d6bf;stroke-width:2.4}
.bg-note{font-size:.74rem;color:var(--muted,#a7b9c9);margin:6px 2px 0}
</style>
<script>
(function(){
  function setup(sec){
    var view=sec.querySelector('.bg-view'), svg=view.querySelector('svg');
    var W=+view.dataset.w, H=+view.dataset.h, s=1, drag=null;
    function apply(){svg.style.width=(W*s)+'px'; svg.style.height=(H*s)+'px';}
    function fit(){return Math.min(1,(view.clientWidth-4)/W);}
    s=Math.max(.6,fit()); apply();
    sec.querySelectorAll('[data-z]').forEach(function(b){b.addEventListener('click',function(){
      var z=b.dataset.z;
      s= z==='+'?Math.min(2,s*1.2) : z==='-'?Math.max(.3,s/1.2) : z==='fit'?fit() : 1; apply();});});
    view.addEventListener('wheel',function(e){ if(!e.ctrlKey) return; e.preventDefault();
      s=Math.max(.3,Math.min(2,s*(e.deltaY<0?1.1:1/1.1))); apply();},{passive:false});
    view.addEventListener('pointerdown',function(e){ if(e.target.closest('.bg-link')) return;
      drag={x:e.clientX,y:e.clientY,l:view.scrollLeft,t:view.scrollTop};
      view.setPointerCapture(e.pointerId); view.classList.add('drag');});
    view.addEventListener('pointermove',function(e){ if(!drag) return;
      view.scrollLeft=drag.l-(e.clientX-drag.x); view.scrollTop=drag.t-(e.clientY-drag.y);});
    ['pointerup','pointercancel'].forEach(function(t){view.addEventListener(t,function(){
      drag=null; view.classList.remove('drag');});});
  }
  function init(){document.querySelectorAll('section.bg').forEach(setup);}
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init); else init();
  window.bgGo=function(pid){ if(window.rvGoProc) rvGoProc(pid); };
  window.bgGoVerdict=function(){ var v=document.querySelector('.va'); if(v) v.scrollIntoView({block:'start'}); };
})();
</script>"""


def behavior_graph_html(result, fallback_pids=None, *, verdict=None, sample_name="", include_evidence=True):
    root, width, height = build_behavior_graph(result, fallback_pids, verdict=verdict,
                                               sample_name=sample_name, include_evidence=include_evidence)
    if not root.children:
        return "<p>그래프로 표시할 행위가 없습니다.</p>"
    nodes = list(walk(root))
    edges = [_draw_edge(p, c) for p in nodes for c in p.children]
    body = []
    for n in nodes:
        tip = f"<title>{escape(n.tip)}</title>" if n.tip else ""
        label = escape(f"{n.label} {n.sub}".strip(), quote=True)
        body.append(f"<g{_attrs(n)} transform='translate({n.left:.1f} {n.top:.1f})' "
                    f"data-node='{n.id}' aria-label='{label}'>{tip}" + "".join(_DRAW[n.kind](n)) + "</g>")
    legend = ("<div class='bg-legend'>"
              f"<span style='--c:{C_MAL}'>악성 근거</span><span style='--c:{C_SUS}'>의심 근거</span>"
              f"<span style='--c:{C_OK}'>일반 행위</span><span style='--c:{C_IDLE}'>행위 없음 · 접힌 항목</span>"
              "</div>")
    zoom = ("<div class='bg-zoom'><button type='button' data-z='-' aria-label='축소'>−</button>"
            "<button type='button' data-z='fit'>맞춤</button><button type='button' data-z='1'>100%</button>"
            "<button type='button' data-z='+' aria-label='확대'>+</button></div>")
    svg = (f"<svg xmlns='http://www.w3.org/2000/svg' width='{width:.0f}' height='{height:.0f}' "
           f"viewBox='0 0 {width:.0f} {height:.0f}' role='img' aria-label='프로세스 실행 흐름과 행위'>"
           "<defs><marker id='bg-arrow' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='7' markerHeight='7' "
           "orient='auto-start-reverse'><path d='M0 0L10 5L0 10z' fill='#5c7290'/></marker></defs>"
           + "".join(edges) + "".join(body) + "</svg>")
    return (_CSS + "<section class='bg' aria-label='행위 그래프'>"
            f"<div class='bg-bar'>{legend}{zoom}</div>"
            f"<div class='bg-view' data-w='{width:.0f}' data-h='{height:.0f}'>{svg}</div>"
            "<p class='bg-note'>프로세스·행위 노드를 누르면 프로세스 상세로, 탐지 근거를 누르면 판정 요약으로 "
            "이동합니다 · 빈 곳을 끌어 이동 · Ctrl+휠로 확대/축소 · 마우스를 올리면 전체 경로와 근거</p></section>")
