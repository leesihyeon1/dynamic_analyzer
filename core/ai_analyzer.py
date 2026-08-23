"""
ai_analyzer.py — 행위 중심 AI 위협 분석 (NVIDIA NIM / Ollama)

동적 분석 결과(프로세스·파일·레지스트리·네트워크·MITRE ATT&CK)를
행위 중심 프롬프트로 변환해 LLM에 전송하고, 위협 분석 텍스트를 반환합니다.

프로바이더:
    nvidia  https://integrate.api.nvidia.com/v1  (OpenAI 호환, API 키 필요)
    ollama  http://localhost:11434               (로컬, 외부 전송 없음)

    provider="auto" 는 NVIDIA 를 먼저 시도하고, 키가 없거나 연결에
    실패하면 Ollama 로 자동 폴백합니다.

주의:
    NVIDIA 사용 시 프롬프트(파일 경로·프로세스명·C2 IP·해시 등)가 외부
    클라우드로 전송됩니다. 격리망/조직 정책을 먼저 확인하세요.
    외부 전송이 불가한 환경에서는 provider="ollama" 로 고정하십시오.

사용:
    from core.ai_analyzer import select_analyzer
    az, notes = select_analyzer(provider="auto")
    if az:
        ai_result = az.analyze(result)
"""
from __future__ import annotations

import json
import os
import re as _re
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── 프로바이더 ───────────────────────────────────────────────────────────────
PROVIDERS = ("nvidia", "ollama")

OLLAMA_BASE_URL      = "http://localhost:11434"
DEFAULT_MODEL        = "qwen2.5:14b"

NVIDIA_BASE_URL      = "https://integrate.api.nvidia.com/v1"
# 한국어 서술 품질 + 파이프 구분 형식 준수 + 낮은 추측성을 기준으로 선정.
# Qwen 계열이 CJK 비중이 높아 Llama 계열보다 한국어 결과물이 자연스럽다.
NVIDIA_DEFAULT_MODEL = "qwen/qwen2.5-72b-instruct"
NVIDIA_API_KEY_ENV   = "NVIDIA_API_KEY"

# 입력 상한 (프로바이더별)
# qwen2.5:14b Q4 (CPU) → 보수적 유지
# 한국어 평균 1.3 chars/token → 안전 상한 약 10,000 자
_MAX_PROMPT_CHARS       = 10_000
# NVIDIA NIM 은 128k 컨텍스트라 여유롭다 (약 30k 토큰 상당)
_MAX_PROMPT_CHARS_CLOUD = 40_000

_MAX_PROMPT_CHARS_BY_PROVIDER = {
    "ollama": _MAX_PROMPT_CHARS,
    "nvidia": _MAX_PROMPT_CHARS_CLOUD,
}

# NVIDIA 는 chat/completions 라 system 메시지를 따로 실을 수 있다.
# Ollama(/api/generate)와 출력 형식을 맞추기 위한 최소 지시만 넣는다.
_NVIDIA_SYSTEM_PROMPT = (
    "당신은 악성코드 동적 분석 결과를 해석하는 위협 인텔리전스 분석가입니다. "
    "반드시 한국어로 답변하고, 사용자가 지정한 섹션 제목과 출력 형식을 그대로 지키십시오. "
    "제공된 데이터에 없는 내용은 추측하거나 지어내지 마십시오."
)


# ── 결과 ─────────────────────────────────────────────────────────────────────

@dataclass
class AiAnalysisResult:
    model:             str   = DEFAULT_MODEL
    provider:          str   = "ollama"  # nvidia | ollama
    response:          str   = ""    # LLM 응답 원문 (마크다운)
    elapsed_sec:       float = 0.0
    prompt_chars:      int   = 0
    error:             str   = ""
    mitre_techniques:  list  = field(default_factory=list)  # 파싱된 MITRE 기법 [{id,name,tactic,evidence}]


# ── Ollama 가용성 확인 ────────────────────────────────────────────────────────

def _is_ollama_running(base_url: str, timeout: int = 4) -> bool:
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def detect_model(base_url: str, timeout: int = 4) -> Optional[str]:
    """현재 Ollama에 로드된 모델을 자동 감지한다.

    1) /api/ps  → 메모리에 올라와 있는(실행 중인) 모델 우선
    2) /api/tags → 설치된 모델 목록의 첫 번째
    둘 다 없으면 None 반환.
    """
    # 1. 현재 실행 중인 모델 (/api/ps, Ollama 0.1.33+)
    try:
        req = urllib.request.Request(f"{base_url}/api/ps", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        models = data.get("models", [])
        if models:
            return models[0].get("name", "")
    except Exception:
        pass

    # 2. 설치된 모델 목록의 첫 번째
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        models = data.get("models", [])
        if models:
            return models[0].get("name", "")
    except Exception:
        pass

    return None


def _is_model_available(base_url: str, model: str, timeout: int = 4) -> bool:
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        names = [m.get("name", "") for m in data.get("models", [])]
        model_base = model.split(":")[0]
        return any(model_base in n for n in names)
    except Exception:
        return False


# ── NVIDIA NIM 가용성 확인 ────────────────────────────────────────────────────

def resolve_nvidia_key(explicit: str = "", cfg_key: str = "") -> str:
    """NVIDIA API 키를 우선순위대로 해석한다.

    1) explicit  — CLI --ai-api-key
    2) 환경변수  — NVIDIA_API_KEY  (권장: config.json 에 평문 저장하지 않음)
    3) cfg_key   — config.json ai.nvidia.api_key
    """
    return (explicit or os.environ.get(NVIDIA_API_KEY_ENV, "") or cfg_key or "").strip()


def _nvidia_headers(api_key: str, stream: bool = False) -> dict:
    h = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    if stream:
        h["Accept"] = "text/event-stream"
    return h


def _is_nvidia_available(base_url: str, api_key: str, timeout: int = 8) -> bool:
    """키 유효성 + 엔드포인트 도달 여부를 GET /models 로 확인한다."""
    if not api_key:
        return False
    try:
        req = urllib.request.Request(
            f"{base_url}/models", method="GET", headers=_nvidia_headers(api_key)
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def list_nvidia_models(base_url: str, api_key: str, timeout: int = 8) -> list:
    """NVIDIA 카탈로그의 모델 ID 목록. 실패 시 빈 리스트."""
    if not api_key:
        return []
    try:
        req = urllib.request.Request(
            f"{base_url}/models", method="GET", headers=_nvidia_headers(api_key)
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        return [m.get("id", "") for m in data.get("data", []) if m.get("id")]
    except Exception:
        return []


def _is_nvidia_model_available(
    base_url: str, api_key: str, model: str, timeout: int = 8
) -> bool:
    """모델이 카탈로그에 있는지 확인. 목록 조회 실패 시에는 통과시킨다."""
    models = list_nvidia_models(base_url, api_key, timeout)
    if not models:
        return True
    return model in models


# NVIDIA 카탈로그는 수시로 바뀐다(모델 추가·제거·ID 변경).
# 설정된 모델이 없을 때 자동으로 대체할 선호 순위 — 앞쪽일수록 이 작업
# (한국어 위협 서술 + 파이프 구분 형식 준수)에 적합하다.
# 정확히 일치하지 않으면 부분 일치로도 찾으므로 버전이 올라가도 잡힌다.
NVIDIA_MODEL_PREFERENCES: tuple[str, ...] = (
    # Qwen 계열 — CJK 비중이 높아 한국어 서술이 가장 자연스럽다
    "qwen/qwen2.5-72b-instruct",
    "qwen/qwen3-235b-a22b",
    "qwen/qwen2.5-32b-instruct",
    "qwen/qwen2-72b-instruct",
    "qwen/",
    # Llama 계열 — 형식 준수는 좋고 한국어는 다소 번역투
    "meta/llama-3.3-70b-instruct",
    "meta/llama-3.1-405b-instruct",
    "meta/llama-3.1-70b-instruct",
    # NVIDIA 튜닝
    "nvidia/llama-3.3-nemotron-super-49b-v1",
    "nvidia/llama-3.1-nemotron-70b-instruct",
    # 기타
    "mistralai/mistral-large",
    "google/gemma-2-27b-it",
)

# 자동 선택에서 배제 — 임베딩·리랭킹·비전·음성 등 대화형이 아닌 모델
_NON_CHAT_HINTS: tuple[str, ...] = (
    "embed", "rerank", "retrieval", "ocr", "asr", "tts", "speech",
    "vision", "vila", "clip", "diffusion", "riva", "nemoguard", "guard",
    "safety", "codestral", "-coder", "embedqa", "parakeet",
)


def _looks_like_ollama_model(model: str) -> bool:
    """Ollama 모델명(qwen2.5:14b)인지 NVIDIA ID(vendor/model)인지 구분."""
    m = (model or "").strip()
    return bool(m) and (":" in m or "/" not in m)


def is_chat_model(model_id: str) -> bool:
    m = (model_id or "").lower()
    return bool(m) and not any(h in m for h in _NON_CHAT_HINTS)


def resolve_nvidia_model(
    base_url: str,
    api_key: str,
    wanted: str = "",
    timeout: int = 8,
) -> tuple:
    """설정된 모델을 실제 카탈로그에 맞춰 해석한다.

    카탈로그에 있으면 그대로 쓰고, 없으면 선호 순위에 따라 자동 대체한다.
    모델 ID 하나가 바뀌었다고 AI 분석 전체가 404 로 죽는 것을 막는 것이 목적.

    Returns
    -------
    (model_id, note)
        note 가 비어 있지 않으면 자동 대체가 일어난 것 — 콘솔에 남긴다.
    """
    catalog = list_nvidia_models(base_url, api_key, timeout)
    if not catalog:
        # 목록 조회 실패 — 판단 근거가 없으므로 설정값 그대로 시도한다
        return (wanted or NVIDIA_DEFAULT_MODEL), ""

    if wanted and wanted in catalog:
        return wanted, ""

    chat_models = [m for m in catalog if is_chat_model(m)]
    pool = chat_models or catalog

    # 1) 선호 목록 정확 일치
    for pref in NVIDIA_MODEL_PREFERENCES:
        if pref in pool:
            return pref, f"모델 '{wanted}' 없음 → '{pref}' 자동 선택"

    # 2) 원하던 모델과 같은 계열 (vendor 및 이름 앞부분 일치)
    if wanted:
        stem = wanted.split(":")[0].rstrip("/")
        for m in pool:
            if m.startswith(stem) or stem in m:
                return m, f"모델 '{wanted}' 없음 → 같은 계열 '{m}' 자동 선택"

    # 3) 선호 목록 부분 일치 (버전 갱신 대응)
    for pref in NVIDIA_MODEL_PREFERENCES:
        key = pref.rstrip("/")
        for m in pool:
            if key in m:
                return m, f"모델 '{wanted}' 없음 → '{m}' 자동 선택"

    # 4) 마지막 수단 — instruct 계열 아무거나
    for m in pool:
        if "instruct" in m.lower():
            return m, f"모델 '{wanted}' 없음 → '{m}' 자동 선택 (카탈로그 임의)"

    if pool:
        return pool[0], f"모델 '{wanted}' 없음 → '{pool[0]}' 자동 선택 (카탈로그 임의)"
    return (wanted or NVIDIA_DEFAULT_MODEL), ""


# ── 내부 유틸 ────────────────────────────────────────────────────────────────

def _tier_filtered(items: list, max_tier: int = 2) -> list:
    """관련도 등급이 max_tier 이하인 항목만, 등급 오름차순으로 반환한다.

    analysis.relevance.annotate() 가 아직 돌지 않았거나 등급이 없는 항목
    (tier 0)은 판정 보류로 보고 남긴다 — 놓치는 것보다 낫다.
    프롬프트 입력 상한이 배경 노이즈로 잠식되는 것을 막는 것이 목적이다.
    """
    kept = []
    for it in items or []:
        t = getattr(it, "relevance_tier", 0) or 0
        if t == 0 or t <= max_tier:
            kept.append(it)
    kept.sort(key=lambda x: (getattr(x, "relevance_tier", 0) or 99))
    return kept


def _tier_mark(obj) -> str:
    """프롬프트에 붙일 등급 표시. 모델이 계보와 배경을 구분하도록 명시한다."""
    t = getattr(obj, "relevance_tier", 0) or 0
    return {1: "[계보] ", 2: "[의심] ", 3: "[배경] "}.get(t, "")


def _paths_by_tier(ioc, max_tier: int = 2, limit: int = 20) -> list:
    """드롭 파일을 관련도 순으로 정렬·필터한다.

    등급은 relevance.annotate() 가 ioc.dropped_file_tiers 에 채워둔다.
    145개 중 대부분이 Windows Update 산출물인 상황에서 앞 12개를 그냥
    자르면 정작 샘플이 떨군 파일이 프롬프트에 들어가지 않는다.
    """
    files = list(getattr(ioc, "dropped_files", []) or [])
    tiers = getattr(ioc, "dropped_file_tiers", None) or {}
    if not tiers:
        return files[:limit]
    kept = [f for f in files if (tiers.get(f, 2) or 2) <= max_tier]
    kept.sort(key=lambda f: (tiers.get(f, 2) or 2, f.lower()))
    return kept[:limit]


def _background_summary(result) -> list:
    """모델이 C2 로 오인하지 않도록 '배경으로 판정된 것' 을 명시한다.

    실제로 이 목록이 없으면 www.msftconnecttest.com(Windows 연결 확인용
    도메인)을 C2 로 지목하는 오답이 반복된다.
    """
    pcap = getattr(result, "pcap_result", None)
    if pcap is None:
        return []
    bg_domains: list[str] = []
    for q in (getattr(pcap, "dns_queries", []) or []):
        if (getattr(q, "relevance_tier", 0) or 0) == 3:
            nm = getattr(q, "name", "")
            if nm and nm not in bg_domains:
                bg_domains.append(nm)
    for h in (getattr(pcap, "http_requests", []) or []):
        if (getattr(h, "relevance_tier", 0) or 0) == 3:
            hs = getattr(h, "host", "")
            if hs and hs not in bg_domains:
                bg_domains.append(hs)
    out = [
        "## 환경 배경 — C2 후보에서 제외할 것",
        "**아래 도메인은 절대 C2 나 악성 인프라로 지목하지 마십시오.**",
    ]
    if bg_domains:
        out.append("- OS·업데이트·텔레메트리: " + ", ".join(bg_domains[:20]))
    # 분석 도구가 스스로 만든 트래픽. 탐지 목적상 화이트리스트에서는 빼두지만,
    # C2 후보로 지목되면 명백한 오답이므로 프롬프트에서 못 박는다.
    out.append(
        "- 분석 인프라(도구 자체 트래픽): system-informer.com, "
        "virustotal.com, abuse.ch, github.com"
    )

    # 관련 외부 통신이 하나도 없으면 '없음' 으로 쓰게 한다.
    rel = [
        c for c in (getattr(pcap, "connections", []) or [])
        if not _is_noise_ip(getattr(c, "dst_ip", ""))
        and (getattr(c, "relevance_tier", 0) or 2) < 3
    ]
    if not rel:
        out.append(
            "**중요: 이번 분석에서 샘플에 귀속되는 외부 통신이 관측되지 않았습니다.** "
            "C2 를 추정해 지어내지 말고 '관측되지 않음' 으로 명시하십시오. "
            "네트워크 활동이 없다는 사실 자체가 유효한 분석 결과입니다."
        )
    out.append("")
    return out


def _trunc(s: str, n: int) -> str:
    s = str(s)
    return s[:n] + "…" if len(s) > n else s


def _fmt_bytes(n: int) -> str:
    if n >= 1_048_576:
        return f"{n/1_048_576:.1f}MB"
    if n >= 1024:
        return f"{n/1024:.1f}KB"
    return f"{n}B"


def _is_private_ip(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or (a == 172 and 16 <= b <= 31)
                or (a == 192 and b == 168) or a == 127)
    except Exception:
        return False


def _is_noise_ip(ip: str) -> bool:
    """C2 후보에서 제외할 IP — 사설 + 멀티캐스트/브로드캐스트/링크로컬.

    _is_private_ip 만으로는 SSDP 멀티캐스트(239.255.255.250:1900)나
    LLMNR/mDNS(224.0.0.x)가 걸러지지 않아 C2 후보 1순위로 올라온다.
    """
    if not ip:
        return True
    if _is_private_ip(ip):
        return True
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return ":" in ip and (ip.lower().startswith("ff") or ip.startswith("fe80"))
        a, b = int(parts[0]), int(parts[1])
        if 224 <= a <= 239:              # 멀티캐스트 (SSDP·mDNS·LLMNR)
            return True
        if a == 255 or ip.endswith(".255"):   # 브로드캐스트
            return True
        if a == 169 and b == 254:        # 링크로컬 (APIPA)
            return True
        if a == 0:
            return True
    except Exception:
        return False
    return False


_RENAME_DEST_RE = _re.compile(r'FileName:\s*([^,\r\n]+)', _re.IGNORECASE)


# ── 태그 사전 계산 ────────────────────────────────────────────────────────────

_IP_CHECK_DOMAINS = frozenset({
    "ip-api.com", "ipify.org", "api.ipify.org", "checkip.amazonaws.com",
    "ipinfo.io", "myexternalip.com", "wtfismyip.com", "icanhazip.com",
    "ipecho.net", "ifconfig.me", "api.myip.com",
})

_MINING_POOL_DOMAINS = frozenset({
    "pool.hashvault.pro", "pool.minexmr.com", "xmrpool.eu", "supportxmr.com",
    "gulf.moneroocean.stream", "mine.xmrpool.net", "moneropool.com",
    "nanopool.org", "2miners.com", "ethermine.org", "f2pool.com",
    "antpool.com", "nicehash.com", "pool.bitcoin.com",
    "xmr.pool.minergate.com", "xmr-eu1.nanopool.org", "xmr-eu2.nanopool.org",
    "xmr-us-east1.nanopool.org", "monero.herominers.com",
})

_DOMAIN_THREAT_LABELS: dict = {
    "pool.hashvault.pro":          "★Monero 채굴 풀 (XMRig)★",
    "pool.minexmr.com":            "★Monero 채굴 풀★",
    "supportxmr.com":              "★Monero 채굴 풀★",
    "xmrpool.eu":                  "★XMR 채굴 풀★",
    "gulf.moneroocean.stream":     "★Monero 채굴 풀★",
    "mine.xmrpool.net":            "★XMR 채굴 풀★",
    "moneropool.com":              "★Monero 채굴 풀★",
    "nanopool.org":                "★채굴 풀★",
    "xmr.pool.minergate.com":      "★Monero 채굴 풀★",
    "nicehash.com":                "★채굴 브로커★",
    "ethermine.org":               "★ETH 채굴 풀★",
    "monero.herominers.com":       "★Monero 채굴 풀★",
}

_STEALER_IDS = frozenset({
    "T1056", "T1539", "T1555", "T1552", "T1114", "T1113",
})
_EVASION_IDS = frozenset({
    "T1497", "T1562", "T1036", "T1027", "T1070", "T1112",
})
_INJECT_IDS = frozenset({
    "T1055", "T1055.001", "T1055.002", "T1055.003", "T1055.011", "T1055.012",
})
_PERSIST_IDS = frozenset({
    "T1053", "T1547", "T1574", "T1543", "T1546", "T1505",
})
_EXFIL_IDS = frozenset({
    "T1041", "T1048", "T1011", "T1020",
})


def _compute_tags(result) -> list[tuple[str, str]]:
    """분석 결과에서 태그(tag, 근거) 목록을 사전 계산한다."""
    tags: list[tuple[str, str]] = []
    technique_ids: set[str] = set()
    # 기법 ID → 사람이 읽는 이름. 태그 근거에 "T1027" 대신
    # "Obfuscated Files or Information" 을 쓰기 위한 매핑.
    # ID 만 나열하면 AI 가 요약에 그대로 복사해 정보량 0 인 문장이 나온다.
    tech_names: dict = {}

    # CAPA 는 바이너리 정적 분석이다. "그런 능력이 있다" 일 뿐 "그 행위를
    # 했다" 가 아니다. 이 둘을 섞으면 행위 분석은 "관찰되지 않음" 인데
    # 요약은 "지속성 기법 사용" 이라고 쓰는 모순이 생긴다.
    static_only_ids: set[str] = set()

    br = result.behavior_report
    if br and getattr(br, "techniques", None):
        for t in br.techniques:
            tid = t.technique_id.split(".")[0]
            _srcs = [s.upper() for s in (getattr(t, "sources", None) or [])]
            _evs  = " ".join(getattr(t, "evidence", None) or [])
            _is_static = (
                bool(_srcs) and all(s == "CAPA" for s in _srcs)
            ) or (not _srcs and _evs.strip().upper() == "CAPA")
            if _is_static:
                static_only_ids.add(t.technique_id)
                static_only_ids.add(tid)
            else:
                technique_ids.add(t.technique_id)
                technique_ids.add(tid)
            nm = getattr(t, "technique_name", "") or ""
            if nm and nm != t.technique_id:
                tech_names.setdefault(t.technique_id, nm)
                tech_names.setdefault(tid, nm)

    # 동적으로 관측된 기법은 정적 목록에서 뺀다 (둘 다 있으면 관측 우선)
    static_only_ids -= technique_ids

    def _names_of(ids, limit: int = 3) -> str:
        """기법 ID 집합 → 이름 목록 문자열 (이름 없으면 ID 폴백)."""
        out: list[str] = []
        for i in sorted(ids):
            nm = tech_names.get(i, "")
            if nm and nm not in out:
                out.append(nm)
            if len(out) >= limit:
                break
        return ", ".join(out) if out else ", ".join(sorted(ids)[:limit])

    # 실행 파일 언어/런타임 (프로세스명 기반)
    new_procs = (result.process_diff or {}).get("new_processes", [])
    proc_names = {getattr(p, "name", "").lower() for p in new_procs}
    if any(n in proc_names for n in ("wscript.exe", "cscript.exe")):
        tags.append(("vbs/js", "WScript 또는 CScript 실행 확인"))
    if "powershell.exe" in proc_names or "pwsh.exe" in proc_names:
        tags.append(("powershell", "PowerShell 실행 확인"))
    if any(n in proc_names for n in ("msbuild.exe", "csc.exe")):
        tags.append(("dotnet", ".NET 컴파일러/빌더 실행 확인"))

    # 네트워크 기반
    pcap = result.pcap_result
    if pcap:
        dns_names = {getattr(q, "name", "").lower() for q in getattr(pcap, "dns_queries", [])}
        if dns_names & _IP_CHECK_DOMAINS:
            matched = dns_names & _IP_CHECK_DOMAINS
            tags.append(("ip-check", f"외부 IP 조회 도메인: {', '.join(sorted(matched)[:2])}"))
        if dns_names & _MINING_POOL_DOMAINS:
            matched = dns_names & _MINING_POOL_DOMAINS
            tags.append(("cryptominer", f"채굴 풀 도메인 DNS 쿼리 확인: {', '.join(sorted(matched)[:3])}"))
        if getattr(pcap, "ftp_sessions", []):
            tags.append(("ftp", f"FTP 세션 {len(pcap.ftp_sessions)}개 감지"))
        if getattr(pcap, "smtp_sessions", []):
            _ss0 = pcap.smtp_sessions[0]
            _ss_doms = (getattr(pcap, "ip_to_domain", {}) or {}).get(_ss0.dst_ip, [])
            _ss_host = _ss_doms[0] if _ss_doms else _ss0.dst_ip
            tags.append(("smtp", f"SMTP C2 유출 — {_ss_host}:{_ss0.dst_port} "
                                  f"{'(인증 확인) ' if _ss0.has_auth else ''}"
                                  f"FROM:{_ss0.mail_from or '?'}"))

    # MITRE 기반
    if technique_ids & _STEALER_IDS:
        tags.append(("stealer", f"자격증명·데이터 탈취 — {_names_of(technique_ids & _STEALER_IDS)}"))
    if technique_ids & _EVASION_IDS:
        tags.append(("evasion", f"방어 회피 — {_names_of(technique_ids & _EVASION_IDS)}"))
    if technique_ids & _INJECT_IDS:
        tags.append(("injection", f"프로세스 인젝션 — {_names_of(technique_ids & _INJECT_IDS)}"))
    if technique_ids & _PERSIST_IDS:
        tags.append(("persistence", f"지속성 — {_names_of(technique_ids & _PERSIST_IDS, 2)}"))
    if technique_ids & _EXFIL_IDS:
        tags.append(("exfiltration", f"데이터 유출 — {_names_of(technique_ids & _EXFIL_IDS, 2)}"))

    # CAPA 정적 능력 — 관측 태그와 분리해서 하나로 묶는다.
    # 개별 태그로 흩뿌리면 모델이 관측된 행위와 구분하지 못한다.
    _static_cats = (
        (_STEALER_IDS, "정보탈취"), (_EVASION_IDS, "방어회피"),
        (_INJECT_IDS, "프로세스인젝션"), (_PERSIST_IDS, "지속성"),
        (_EXFIL_IDS, "데이터유출"),
    )
    _static_hits: list[str] = []
    for _ids, _label in _static_cats:
        if static_only_ids & _ids:
            _static_hits.append(f"{_label}({_names_of(static_only_ids & _ids, 2)})")
    if _static_hits:
        tags.append((
            "static-capability",
            "정적 분석(CAPA)에서만 확인된 능력 — 실행 중 관측되지 않음: "
            + " / ".join(_static_hits[:4]),
        ))

    # 드롭 파일
    ioc = result.ioc_report
    if ioc and ioc.dropped_files:
        tags.append(("dropper", f"파일 드롭 {len(ioc.dropped_files)}개"))

    # 이메일/피싱 컨텍스트 (T1221 템플릿 인젝션 = 문서 기반 배포)
    if "T1221" in technique_ids:
        tags.append(("phishing", "문서 템플릿 인젝션 (T1221) — 이메일 기반 배포 가능성"))

    return tags


# ── AI MITRE 파싱 + 병합 ─────────────────────────────────────────────────────

_TOOL_EVIDENCE_TOKENS: tuple[str, ...] = (
    "procmon", "procexp", "pe-sieve", "pe_sieve", "hollows_hunter",
    "hollows-hunter", "systeminformer", "processhacker", "tshark",
    "dumpcap", "wireshark", "zoomit", "winpmem", "volatility",
)


def _is_tool_evidence(text: str) -> bool:
    t = (text or "").lower()
    return any(tok in t for tok in _TOOL_EVIDENCE_TOKENS)


def parse_mitre_from_ai(response: str) -> list:
    """AI 응답의 '마이터 기법 목록' 섹션을 파싱해 구조화된 기법 목록을 반환한다.

    형식: T기법ID|기법명(영문)|전술명(영문)|구체적 근거
    """
    results: list = []
    in_section = False
    _NEXT_SECTIONS = frozenset({
        "분석 분류", "핵심 요약", "실행 흐름", "행위 분석", "확인된 IOC", "결론",
        "Analytical classification", "Executive summary",
        "Execution flow", "Behavioral analysis", "Conclusion",
    })
    for line in response.split("\n"):
        stripped = line.strip()
        head     = _strip_heading_mark(stripped)
        if head == "마이터 기법 목록":
            in_section = True
            continue
        if not in_section:
            continue
        if not stripped:
            break  # 빈 줄 = 섹션 끝
        if stripped == "없음":
            break
        if head in _NEXT_SECTIONS:
            break
        parts = [p.strip() for p in stripped.split("|")]
        if len(parts) >= 4:
            tid = parts[0]
            if not _re.match(r"^T\d{4}(\.\d{3})?$", tid):
                continue
            name, tactic, evidence = parts[1], parts[2], parts[3]
            # 모델이 기법명을 모를 때 ID 를 그대로 되뱉거나 전술을 Unknown 으로
            # 채우는 경우가 있다(T1125|T1125|Unknown). 이런 항목은 리포트에
            # 병합되면 그냥 쓰레기 행이 되므로 버린다.
            if name == tid or not name:
                continue
            if tactic.lower() in ("unknown", "unknown tactic", "n/a", "-", ""):
                continue
            # 분석 도구를 근거로 든 항목도 제외 (hollows_hunter.exe 등)
            if _is_tool_evidence(evidence):
                continue
            results.append({
                "id":       tid,
                "name":     name,
                "tactic":   tactic,
                "evidence": evidence,
            })
    return results


def merge_ai_mitre(behavior_report, ai_techniques: list) -> None:
    """AI 분석에서 추출한 MITRE 기법을 behavior_report에 병합한다.

    - 이미 존재하는 technique_id → 'AI' 소스와 증거만 추가
    - 새 기법 → MitreTechnique 생성 후 추가, 전술순 재정렬
    """
    if not behavior_report or not ai_techniques:
        return
    try:
        from analysis.behavior_classifier import MitreTechnique, _tactic_key
    except ImportError:
        return

    existing_map = {t.technique_id: t for t in behavior_report.techniques}
    added = False

    for item in ai_techniques:
        tid    = item.get("id", "")
        tname  = item.get("name", "")
        tactic = item.get("tactic", "")
        tevid  = item.get("evidence", "")
        if not tid or not tname or not tactic:
            continue

        ai_ev = f"[AI] {tevid}" if tevid else "[AI]"

        if tid in existing_map:
            t = existing_map[tid]
            if ai_ev not in t.evidence:
                t.evidence.append(ai_ev)
            if "AI" not in t.sources:
                t.sources.append("AI")
        else:
            ref = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            new_t = MitreTechnique(
                technique_id   = tid,
                technique_name = tname,
                tactic         = tactic,
                evidence       = [ai_ev],
                reference      = ref,
                sources        = ["AI"],
            )
            behavior_report.techniques.append(new_t)
            existing_map[tid] = new_t
            added = True

    if added:
        behavior_report.techniques.sort(key=_tactic_key)


# ── 행위 분석 섹션 빌더 (데이터 기반, AI 할루시네이션 방지) ─────────────────────

def _build_behavioral_text(result) -> str:
    """'행위 분석' 섹션을 분석 데이터에서 직접 계산한다.

    AI에게 맡기면 7b 모델이 훈련 데이터의 일반적 악성코드 패턴으로 채워버리므로
    Python에서 확인된 사실만 기술한다.
    필드명은 html_report.py _render_behavioral FIELDS와 정확히 일치해야 한다.
    """
    parts: list[str] = ["행위 분석"]

    new_procs = (result.process_diff or {}).get("new_processes", []) if result.process_diff else []
    sample_name = "샘플"
    if getattr(result.config, "sample_path", None):
        sample_name = Path(result.config.sample_path).name
    pcap = getattr(result, "pcap_result", None)

    # 로더 / 스테이징
    # 계보(Tier 1) 프로세스가 쓴 실행 파일만 페이로드로 본다.
    # 필터가 없으면 Explorer 가 Temp 에 푼 Procmon64.exe(분석 도구)나
    # 시스템 DLL 이 "샘플이 드롭한 페이로드" 로 서술된다.
    _lineage = set(getattr(result, "lineage_pids", None) or [])
    try:
        from parsers.procmon_csv import EventCategory as _EC2
        _cand = [
            ev for ev in (result.filtered_events or [])
            if ev.category == _EC2.FILE
            and ev.operation in ("WriteFile", "CreateFile")
            and any(ev.path.lower().endswith(ext) for ext in (".ps1", ".vbs", ".bat", ".js", ".hta", ".exe", ".dll"))
            and getattr(ev, "result", "") == "SUCCESS"
            and not _is_tool_evidence(ev.path)
        ]
        # 계보가 쓴 것 우선, 없으면 전체에서 (도구 흔적은 이미 제외됨)
        _lin_drops = [ev.path for ev in _cand if getattr(ev, "pid", None) in _lineage]
        _drop_files = list(dict.fromkeys(_lin_drops or [ev.path for ev in _cand]))[:4]
        _drops_from_lineage = bool(_lin_drops)
    except Exception:
        _drop_files, _drops_from_lineage = [], False
    if _drop_files:
        _drops_str = ", ".join(_trunc(f, 70) for f in _drop_files[:2])
        _who = sample_name if _drops_from_lineage else "분석 중 관측된 프로세스"
        parts.append(f"로더 / 스테이징: {_who}가 실행되어 페이로드를 드롭 — {_drops_str}")
    else:
        parts.append(f"로더 / 스테이징: {sample_name}가 실행됨")

    # 실행 및 피벗 (LOLBin)
    _LOLBINS = {"wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe",
                "mshta.exe", "regsvr32.exe", "rundll32.exe", "cmd.exe"}
    _lolbins_seen = list(dict.fromkeys([
        getattr(p, "name", "") for p in new_procs
        if getattr(p, "name", "").lower() in _LOLBINS
    ]))
    if _lolbins_seen:
        parts.append(f"실행 및 피벗 (LOLBin / 인터프리터): {' → '.join(_lolbins_seen)}")
    else:
        parts.append("실행 및 피벗 (LOLBin / 인터프리터): 관찰되지 않음")

    # 지속성 — 실제 확인된 경우만 기술
    _reg_diff = result.registry_diff or {}
    _PERSIST_REG = ("\\run\\", "\\runonce\\", "\\currentversion\\run")
    _persist_reg = [
        r[0] for r in (_reg_diff.get("added", []) or []) + (_reg_diff.get("modified", []) or [])
        if any(k in str(r[0]).lower() for k in _PERSIST_REG)
    ]
    _persist_procs = [
        p for p in new_procs
        if getattr(p, "name", "").lower() in {"schtasks.exe", "sc.exe", "at.exe"}
    ]
    if _persist_reg:
        parts.append(f"지속성 (관찰된 경우): 레지스트리 Run 키 — {_trunc(str(_persist_reg[0]), 80)}")
    elif _persist_procs:
        _pp = _persist_procs[0]
        _pp_cmd = " ".join(getattr(_pp, "cmdline", []) or []) or getattr(_pp, "exe", "")
        parts.append(f"지속성 (관찰된 경우): {getattr(_pp,'name','')} — {_trunc(_pp_cmd, 80)}")
    else:
        parts.append("지속성 (관찰된 경우): 관찰되지 않음")

    # 메모리 인젝션
    _hh = getattr(result, "hh_result", None)
    _pe_list = getattr(result, "pe_sieve_results", []) or []
    _hh_susp: list = []
    if _hh and not getattr(_hh, "error", ""):
        _hh_susp = [r for r in (getattr(_hh, "process_results", []) or []) if getattr(r, "suspicious", 0) > 0]
    _pe_susp = [r for r in _pe_list if not getattr(r, "error", "") and getattr(r, "suspicious", 0) > 0]
    # 신뢰도 판정 결과가 있으면 그것을 우선 사용한다.
    # relevance.classify_injections() 가 베이스라인·탐지유형·계보를 종합해
    # HIGH/MEDIUM/LOW 를 매겨두므로, 오탐(LOW)을 확정 서술하지 않는다.
    _inj = getattr(result, "injection_findings", None) or []
    if _inj:
        _hi  = [f for f in _inj if f["confidence"] == "HIGH"]
        _mid = [f for f in _inj if f["confidence"] == "MEDIUM"]
        _low = [f for f in _inj if f["confidence"] == "LOW"]

        def _fmt(fs, n=3):
            return ", ".join(f"{f['name']}(PID {f['pid']})" for f in fs[:n])

        if _hi:
            _seg = f"샘플 계보 내 주입 확인 — {_fmt(_hi)}"
        elif _mid:
            _seg = f"주입 의심(미확인) — {_fmt(_mid)}"
        else:
            _seg = "확인된 주입 없음"
        if _low:
            _seg += (
                f" / 오탐 추정 {len(_low)}건 제외"
                f" ({_fmt(_low, 2)} — {_low[0]['reason']})"
            )
        parts.append(f"메모리 인젝션 (관찰된 경우): {_seg}")
    else:
        # 폴백 — 관련도 판정이 돌지 않은 경우에도 도구 자기 탐지와
        # 계보 밖 탐지는 구분해서 쓴다.
        _hh_susp = [r for r in _hh_susp if not _is_tool_evidence(getattr(r, "name", ""))]
        _pe_susp = [r for r in _pe_susp if not _is_tool_evidence(getattr(r, "name", ""))]
        _all = _hh_susp or _pe_susp
        if not _all:
            parts.append("메모리 인젝션 (관찰된 경우): 관찰되지 않음")
        else:
            _in_lin  = [r for r in _all if getattr(r, "pid", None) in _lineage]
            _out_lin = [r for r in _all if getattr(r, "pid", None) not in _lineage]
            if _in_lin:
                _nm = ", ".join(f"{getattr(r,'name','?')}(PID {getattr(r,'pid',0)})" for r in _in_lin[:3])
                parts.append(
                    f"메모리 인젝션 (관찰된 경우): 샘플 계보 내 탐지 — {_nm}"
                    + (f" / 계보 밖 {len(_out_lin)}건은 오탐 가능성 높음(미확인)" if _out_lin else "")
                )
            else:
                parts.append(
                    f"메모리 인젝션 (관찰된 경우): 샘플 계보 내 탐지 없음 "
                    f"(계보 밖 {len(_out_lin)}건은 JIT·ASLR 오탐 추정, 미확인)"
                )

    # 레지스트리 변경 — 지금까지 슬롯이 없어 관측돼도 서술에서 누락됐다.
    # (T1112 Modify Registry 가 요약에만 뜨고 행위 분석엔 없던 원인)
    _REG_WRITE_OPS = {"RegSetValue", "RegCreateKey", "RegDeleteValue", "RegDeleteKey"}
    try:
        from parsers.procmon_csv import EventCategory as _EC3
        _reg_lin = list(dict.fromkeys([
            ev.path for ev in (result.filtered_events or [])
            if ev.category == _EC3.REGISTRY
            and ev.operation in _REG_WRITE_OPS
            and getattr(ev, "result", "") == "SUCCESS"
            and getattr(ev, "pid", None) in _lineage
        ]))
    except Exception:
        _reg_lin = []
    if _reg_lin:
        parts.append(
            f"레지스트리 변경 (관찰된 경우): 샘플 계보가 {len(_reg_lin)}개 키 변경 — "
            + ", ".join(_trunc(k, 70) for k in _reg_lin[:2])
        )
    else:
        parts.append("레지스트리 변경 (관찰된 경우): 샘플 계보의 변경 없음")

    # 탐색 / 수집
    # 오탐(LOW)으로 판정된 주입 탐지를 근거로 "정보탈취 추정" 을 쓰면 안 된다.
    # 신뢰도 HIGH/MEDIUM 만 근거로 인정한다.
    if _inj:
        _credible = [f for f in _inj if f["confidence"] in ("HIGH", "MEDIUM")]
        _cred_nm  = ", ".join(f["name"] for f in _credible[:2])
    else:
        _credible = [r for r in _hh_susp if getattr(r, "pid", None) in _lineage]
        _cred_nm  = ", ".join(getattr(r, "name", "?") for r in _credible[:2])

    _smtp_ss = getattr(pcap, "smtp_sessions", []) or [] if pcap else []
    if _credible and _smtp_ss:
        parts.append(
            f"탐색 / 수집 (관찰된 경우): {_cred_nm}(주입 의심) → SMTP로 데이터 유출 "
            f"— 키로거/정보탈취 추정"
        )
    elif _credible:
        parts.append(
            f"탐색 / 수집 (관찰된 경우): 주입 의심 프로세스 {len(_credible)}건 "
            f"({_cred_nm}) — 수집 행위 상세 불명"
        )
    else:
        parts.append("탐색 / 수집 (관찰된 경우): 관찰되지 않음")

    # 네트워크 / C2
    if pcap and _smtp_ss:
        _s0      = _smtp_ss[0]
        _ip2dom  = getattr(pcap, "ip_to_domain", {}) or {}
        _doms    = _ip2dom.get(_s0.dst_ip, [])
        _host    = _doms[0] if _doms else _s0.dst_ip
        _auth    = f"AUTH:{_s0.auth_user}" if _s0.auth_user else ("AUTH확인됨" if _s0.has_auth else "")
        _c2_seg  = [f"{_host}:{_s0.dst_port} (SMTP"]
        if _s0.mail_from: _c2_seg.append(f"FROM:{_s0.mail_from}")
        if _auth:         _c2_seg.append(_auth)
        if _s0.has_data:  _c2_seg.append("DATA전송완료")
        parts.append(f"네트워크 / C2 또는 유출 (관찰된 경우): {', '.join(_c2_seg)})")
    elif pcap:
        _conns  = getattr(pcap, "connections", []) or []
        _ext    = [c for c in _conns if not _is_noise_ip(c.dst_ip)]
        # 환경 배경(Tier 3)을 뺀 관련 연결만 대표로 내세운다.
        # 필터가 없으면 Windows 연결확인용 msftconnecttest.com 이
        # "C2 또는 유출" 자리에 그대로 올라간다.
        _rel = [c for c in _ext if (getattr(c, "relevance_tier", 0) or 2) < 3]
        _rel.sort(key=lambda c: (getattr(c, "relevance_tier", 0) or 2,
                                 0 if getattr(c, "suspicious_port", False) else 1,
                                 -int(getattr(c, "bytes_out", 0) or 0)))
        if _rel:
            _ip2dom2 = getattr(pcap, "ip_to_domain", {}) or {}
            _d2      = _ip2dom2.get(_rel[0].dst_ip, [])
            _h2      = (_d2[0] if isinstance(_d2, (list, tuple)) and _d2 else (_d2 or _rel[0].dst_ip))
            parts.append(
                f"네트워크 / C2 또는 유출 (관찰된 경우): 관련 외부 연결 {len(_rel)}건"
                f" (전체 {len(_ext)}건) — 대표 {_h2}:{_rel[0].dst_port}"
            )
        elif _ext:
            parts.append(
                f"네트워크 / C2 또는 유출 (관찰된 경우): 외부 연결 {len(_ext)}건 모두 "
                f"환경 배경(OS·업데이트·텔레메트리)으로 판정 — 샘플 귀속 통신 없음"
            )
        else:
            parts.append("네트워크 / C2 또는 유출 (관찰된 경우): 활동 없음")
    else:
        parts.append("네트워크 / C2 또는 유출 (관찰된 경우): 관찰되지 않음")

    # 정적 능력 (CAPA) — 관측 항목과 명확히 분리해 마지막에 붙인다.
    # 이 줄이 없으면 CAPA 결과가 요약에만 등장해 "요약엔 있는데 행위 분석엔
    # 없다" 는 모순으로 보인다. 실제로는 정적 능력이라 관측 슬롯에 못 들어간다.
    _br2 = getattr(result, "behavior_report", None)
    _static_names: list[str] = []
    for _t in (getattr(_br2, "techniques", None) or []):
        _s = [x.upper() for x in (getattr(_t, "sources", None) or [])]
        if _s and all(x == "CAPA" for x in _s):
            _n = getattr(_t, "technique_name", "") or ""
            if _n and _n != getattr(_t, "technique_id", "") and _n not in _static_names:
                _static_names.append(_n)
    if _static_names:
        parts.append(
            f"정적 능력 (CAPA, 미관측): {', '.join(_static_names[:6])}"
            + (f" 외 {len(_static_names) - 6}건" if len(_static_names) > 6 else "")
            + " — 바이너리에 해당 코드가 존재하나 이번 실행에서 수행되지 않음"
        )
    else:
        parts.append("정적 능력 (CAPA, 미관측): 없음")

    # 오류 / 크래시
    parts.append("오류 / 크래시 (관찰된 경우): 관찰되지 않음")

    return "\n".join(parts)


def _build_ioc_text(result) -> str:
    """'확인된 IOC' 섹션을 데이터에서 직접 생성한다.

    모델에게 C2 를 고르게 하면 www.msftconnecttest.com(윈도우 연결 확인용
    도메인) 같은 배경 트래픽을 지목하는 오답이 반복된다. C2 후보는 관련도
    등급과 포트·귀속 프로세스로 결정론적으로 순위를 매길 수 있으므로
    AI 판단을 쓰지 않는다.
    """
    parts = ["확인된 IOC"]
    pcap  = getattr(result, "pcap_result", None)
    ioc   = getattr(result, "ioc_report", None)

    # ── C2 후보 ──────────────────────────────────────────────────────
    pnmap = getattr(result, "process_network_map", []) or []
    ip_procs: dict = {}
    for pn in pnmap:
        ip_procs.setdefault(getattr(pn, "remote_ip", ""), []).append(
            getattr(pn, "process", "")
        )

    cands: list[tuple] = []
    if pcap is not None:
        for c in (getattr(pcap, "connections", []) or []):
            ip = getattr(c, "dst_ip", "")
            # 사설·멀티캐스트·브로드캐스트는 C2 후보가 될 수 없다
            if _is_noise_ip(ip):
                continue
            tier = getattr(c, "relevance_tier", 0) or 2
            if tier >= 3:                       # 환경 배경은 C2 후보 아님
                continue
            port = getattr(c, "dst_port", 0)
            susp = bool(getattr(c, "suspicious_port", False))
            procs = sorted(set(p for p in ip_procs.get(ip, []) if p))
            # 정렬 키: 계보 우선 → 의심 포트 → 송신량
            cands.append((
                tier, 0 if susp else 1, -int(getattr(c, "bytes_out", 0) or 0),
                ip, port, procs,
            ))
    cands.sort()

    if cands:
        _lines = []
        for item in cands[:5]:
            tier, _s, _b, ip, port, procs = item
            mark = {1: "[계보]", 2: "[의심]"}.get(tier, "")
            pstr = f" ← {', '.join(procs[:3])}" if procs else ""
            _lines.append(f"  - {mark} {ip}:{port}{pstr}")
        parts.append("C2 후보 (관련도 순, 배경 트래픽 제외):")
        parts.extend(_lines)
    else:
        parts.append(
            "C2 후보: 없음 — 샘플에 귀속되는 외부 통신이 관측되지 않았습니다 "
            "(사설/멀티캐스트 트래픽과 환경 배경은 제외)"
        )

    # ── 드롭 파일 (계보 우선) ────────────────────────────────────────
    if ioc is not None and getattr(ioc, "dropped_files", None):
        drops = _paths_by_tier(ioc, max_tier=2, limit=6)
        if drops:
            parts.append("드롭 파일 (샘플 관련):")
            parts.extend(f"  - {_trunc(d, 130)}" for d in drops)
        else:
            parts.append("드롭 파일: 샘플 관련 드롭 없음 (전체는 환경 배경)")
    else:
        parts.append("드롭 파일: 없음")

    # ── 뮤텍스 ───────────────────────────────────────────────────────
    mtx = list(getattr(ioc, "mutexes", []) or []) if ioc is not None else []
    parts.append("뮤텍스 / 기타: " + (", ".join(mtx[:5]) if mtx else "없음"))

    return "\n".join(parts)


def _inject_behavioral_section(ai_response: str, behavioral_text: str) -> str:
    """AI 응답에서 '행위 분석' 섹션을 Python 계산값으로 교체한다.

    AI가 쓴 '행위 분석'이 있으면 그 범위를 교체하고, 없으면 '결론' 앞에 삽입한다.
    """
    return _replace_section(ai_response, "행위 분석", behavioral_text,
                            fallback_before=("결론", "마이터 기법 목록"))


_SECTION_TITLES = [
    "분석 분류", "핵심 요약", "실행 흐름", "행위 분석",
    "확인된 IOC", "결론", "마이터 기법 목록",
]

# 모델이 프롬프트 형식을 무시하고 '## 실행 흐름' / '**결론**' 처럼 제목에
# 마크다운 표식을 붙이는 경우가 있다. 맨 제목만 매칭하면 섹션을 전부 놓쳐
# 리포트에서 사라지므로 표식을 허용한다.
_HEAD_MARK = r"(?:#{1,6}[ \t]*(?:\*\*)?|\*\*)"
_HEADING_MARK_RE = _re.compile(
    r"^[ \t]{0,3}(?:#{1,6}[ \t]*)?(?:\*\*)?(.*?)\**[ \t]*:?[ \t]*$"
)


def _strip_heading_mark(line: str) -> str:
    """제목 줄에서 마크다운 표식(#, **)과 후행 콜론을 제거한다."""
    m = _HEADING_MARK_RE.match(line.strip())
    return m.group(1).strip() if m else line.strip()


def _section_boundary_re(titles: list) -> "_re.Pattern":
    """표식을 허용하는 섹션 제목 경계 정규식."""
    _pat = "|".join(_re.escape(t) for t in titles)
    return _re.compile(
        r"^[ \t]{0,3}" + _HEAD_MARK + r"?(" + _pat + r")\**[ \t]*:?[ \t]*$",
        _re.MULTILINE,
    )

_TID_RE = _re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _expand_technique_ids(response: str, result) -> str:
    """서술 섹션의 기법 ID 를 기법 이름으로 치환한다.

    "T1027, T1112 기법이 사용되었습니다" 같은 문장은 읽는 사람에게 아무
    정보도 주지 않는다. 프롬프트로 금지해도 모델이 종종 어기므로 후처리로
    보정한다. 삭제하면 문장이 깨지므로 이름으로 바꾼다.

    "마이터 기법 목록" 섹션은 ID 가 데이터 형식 자체이므로 건드리지 않는다.
    """
    br = getattr(result, "behavior_report", None)
    id2name: dict = {}
    for t in (getattr(br, "techniques", None) or []):
        tid = getattr(t, "technique_id", "")
        nm  = getattr(t, "technique_name", "")
        if tid and nm and nm != tid:
            id2name[tid] = nm
            id2name.setdefault(tid.split(".")[0], nm)
    if not id2name:
        return response

    _splits = list(_section_boundary_re(_SECTION_TITLES).finditer(response))
    if not _splits:
        return response

    def _sub(text: str) -> str:
        return _TID_RE.sub(lambda m: id2name.get(m.group(0), m.group(0)), text)

    out    = [response[:_splits[0].start()]]
    for i, m in enumerate(_splits):
        end   = _splits[i + 1].start() if i + 1 < len(_splits) else len(response)
        chunk = response[m.start():end]
        # 기법 목록 섹션은 ID 유지
        out.append(chunk if m.group(1) == "마이터 기법 목록" else _sub(chunk))
    return "".join(out)


def _replace_section(
    ai_response: str,
    title: str,
    new_text: str,
    fallback_before: tuple = ("결론", "마이터 기법 목록"),
) -> str:
    """AI 응답의 특정 섹션을 계산값으로 교체한다.

    해당 섹션이 있으면 통째로 바꾸고, 없으면 fallback_before 섹션 앞에 삽입한다.
    할루시네이션 억제용 — 데이터로 확정할 수 있는 항목은 AI 판단을 쓰지 않는다.
    """
    _splits = list(_section_boundary_re(_SECTION_TITLES).finditer(ai_response))

    for i, m in enumerate(_splits):
        if m.group(1) == title:
            end = _splits[i + 1].start() if i + 1 < len(_splits) else len(ai_response)
            return ai_response[:m.start()] + new_text + "\n\n" + ai_response[end:]

    for m in _splits:
        if m.group(1) in fallback_before:
            return ai_response[:m.start()] + new_text + "\n\n" + ai_response[m.start():]

    return ai_response + "\n\n" + new_text


# ── 프롬프트 빌더 ────────────────────────────────────────────────────────────

def _build_prompt(result, max_chars: int = _MAX_PROMPT_CHARS) -> str:
    """AnalysisResult → 구조화된 위협 분석 프롬프트 (any.run 스타일)."""
    lines: list[str] = [
        "당신은 악성코드 동적 분석 전문가입니다.",
        "아래 동적 분석 데이터를 바탕으로 **한국어**로 구조화된 위협 분석 보고서를 작성하세요.",
        "대응 권고는 절대 작성하지 않습니다. 확인된 사실만 기술하고 추측은 '추정' 표현을 사용하세요.",
        "섹션 제목은 아래 템플릿의 문구를 그대로 한 줄에 쓰십시오. 제목 줄에 #, *, - 를"
        " 붙이지 마십시오. 하위 필드(위협 수준 등)는 제목으로 분리하지 말고"
        " '필드명: 값' 한 줄로 쓰십시오.",
        "",
    ]

    # ── 분석 대상 ────────────────────────────────────────────────────────
    sample_name = "전체 시스템 모니터링"
    if getattr(result.config, "sample_path", None):
        sample_name = Path(result.config.sample_path).name
    pid_str = f" (PID: {result.sample_pid})" if result.sample_pid else ""
    all_pids = sorted(result.all_pids) if result.all_pids else []

    lines.append("## 분석 대상")
    lines.append(f"- 파일명: {sample_name}{pid_str}  ← 분석 진입점 (이 파일 자체가 로더/드롭퍼)")
    # 경로를 명시하지 않으면 모델이 드롭 파일 목록에서 아무 경로나 골라
    # "샘플이 StartUp 폴더에서 실행됨" 같은 없는 사실을 지어낸다.
    _spath = getattr(getattr(result, "config", None), "sample_path", None)
    if _spath:
        lines.append(f"- 실제 경로: {_spath}  ← 이 경로만 샘플의 위치임. 다른 경로를 샘플 위치로 쓰지 말 것")
    # 샘플 계보를 못 박아 둔다 — 배경 프로세스를 샘플 행위로 귀속시키는 오답 방지
    _lin = sorted(getattr(result, "lineage_pids", None) or [])
    if _lin:
        _lin_names = []
        for p in (result.process_diff or {}).get("new_processes", []):
            if getattr(p, "pid", None) in set(_lin):
                _lin_names.append(f"{getattr(p, 'name', '?')}({getattr(p, 'pid', '?')})")
        if _lin_names:
            lines.append(
                f"- 샘플 계보: {', '.join(_lin_names)}"
                f"  ← 이 프로세스들의 행위만 샘플 소행으로 단정할 수 있음"
            )
    lines.append(
        "- 실행 방법: 분석 도구가 샘플을 직접 실행했습니다. "
        "분석 도구(python.exe, procmon, pe-sieve, tshark 등)의 동작을 "
        "공격자 행위나 사용자 행위로 서술하지 마십시오."
    )
    if all_pids:
        lines.append(f"- 추적 PID: {', '.join(str(p) for p in all_pids[:20])}")
    lines.append("")

    # ── MITRE ATT&CK (전술별 그룹) ──────────────────────────────────────
    br = result.behavior_report
    if br and getattr(br, "techniques", None):
        techs = br.techniques
        tactic_groups: dict[str, list] = {}
        for t in techs:
            tactic_groups.setdefault(t.tactic, []).append(t)
        lines.append(f"## MITRE ATT&CK ({len(techs)}건)")
        lines.append("[정적] = CAPA 정적 분석(코드 존재, 미관측) / [관측] = 실행 중 실제 관측")
        for tactic, ts in tactic_groups.items():
            lines.append(f"### {tactic}")
            for t in ts[:5]:
                ev    = t.evidence[:1]
                ev_str = f" → {_trunc(ev[0], 80)}" if ev else ""
                _s = [x.upper() for x in (getattr(t, "sources", None) or [])]
                _mk = "[정적]" if (_s and all(x == "CAPA" for x in _s)) else "[관측]"
                lines.append(f"- {_mk} [{t.technique_id}] {t.technique_name}{ev_str}")
        lines.append("")

    # ── 프로세스 실행 체인 + 행위 상세 ────────────────────────────────────
    # 환경 배경(Tier 3)은 프롬프트에서 제외한다. Windows Update 하나가 돌면
    # 프로세스 80여 개가 입력 상한을 잠식해 정작 샘플 계보가 잘려 나간다.
    new_procs = _tier_filtered(
        (result.process_diff or {}).get("new_processes", [])
    )
    if new_procs:
        # PID→이름 맵: 사후 전체 스냅샷(부모 포함) + 신규 프로세스
        _pid_to_nm: dict[int, str] = {}
        for _pid, _ps in (getattr(result, "proc_after_snapshot", {}) or {}).items():
            _pid_to_nm[_pid] = getattr(_ps, "name", "?")
        for _np in new_procs:
            _pid_to_nm[getattr(_np, "pid", 0)] = getattr(_np, "name", "?")

        # 신규 프로세스 PID 집합
        _new_pids: set[int] = {getattr(p, "pid", 0) for p in new_procs}

        # 부모→자식 관계 구성 (신규 프로세스 내부 관계)
        _children: dict[int, list] = {}
        _roots: list[int] = []
        for _np in new_procs:
            _pp = getattr(_np, "ppid", 0)
            _cp = getattr(_np, "pid", 0)
            if _pp in _new_pids:
                _children.setdefault(_pp, []).append(_cp)
            else:
                _roots.append(_cp)

        # 체인 트리 DFS 출력
        def _chain_lines(pid: int, depth: int = 0) -> list[str]:
            pname  = _pid_to_nm.get(pid, "?")
            prefix = ("  " * depth) + ("→ " if depth else "")
            rows   = [f"{prefix}{pname}({pid})"]
            for child in _children.get(pid, []):
                rows.extend(_chain_lines(child, depth + 1))
            return rows

        chain_rows: list[str] = []
        for rp in _roots:
            chain_rows.extend(_chain_lines(rp))

        lines.append(f"## 프로세스 실행 체인 ← 공격 흐름 파악 핵심 (신규 {len(new_procs)}개)")
        lines.extend(chain_rows[:30])
        lines.append("")

        # 명령줄 상세 (부모 이름 주석 포함)
        lines.append("## 프로세스 행위 상세")
        for p in new_procs[:15]:
            name  = getattr(p, "name", "?")
            pid   = getattr(p, "pid", "?")
            ppid  = getattr(p, "ppid", 0)
            pname = _pid_to_nm.get(ppid, f"PID {ppid}")
            exe   = getattr(p, "exe", "") or ""
            cmd   = " ".join(getattr(p, "cmdline", []) or []) or exe
            lines.append(f"- {name} (PID {pid}, 부모: {pname}): {_trunc(cmd, 100)}")
        lines.append("")

        # ── 프로세스별 악성 행위 요약 ──────────────────────────────────────
        # EventCategory import
        try:
            from parsers.procmon_csv import EventCategory as _EC
            _FILE_CAT = _EC.FILE
            _REG_CAT  = _EC.REGISTRY
            _ec_ok    = True
        except Exception:
            _FILE_CAT = _REG_CAT = None
            _ec_ok = False

        # PID별 파일/레지스트리 이벤트 그룹화
        _pid_fevs: dict[int, list] = {}
        _pid_revs: dict[int, list] = {}
        if _ec_ok:
            _FILE_OPS_PP = {"WriteFile", "CreateFile", "DeleteFile"}
            for _ev in (result.filtered_events or []):
                _evpid = getattr(_ev, "pid", 0)
                if _evpid not in _new_pids:
                    continue
                _evc = getattr(_ev, "category", None)
                _evo = getattr(_ev, "operation", "")
                if _evc == _FILE_CAT and _evo in _FILE_OPS_PP:
                    _pid_fevs.setdefault(_evpid, []).append(_ev)
                elif _evc == _REG_CAT and _evo == "RegSetValue":
                    _pid_revs.setdefault(_evpid, []).append(_ev)

        # PID별 네트워크 연결 그룹화
        _pid_nets: dict[int, list] = {}
        for _pnc in (getattr(result, "process_network_map", []) or []):
            _pncpid = getattr(_pnc, "pid", 0)
            if _pncpid in _new_pids:
                _pid_nets.setdefault(_pncpid, []).append(_pnc)

        # PID별 DNS 귀속 그룹화
        _pid_dns: dict[int, list] = {}
        for _dq in (getattr(result, "dns_attributed", []) or []):
            _dqpid = getattr(_dq, "pid", 0)
            if _dqpid in _new_pids and getattr(_dq, "attributed", False):
                _pid_dns.setdefault(_dqpid, []).append(_dq)

        # PID별 hollows-hunter 인젝션 결과 그룹화
        _pid_hh2: dict[int, object] = {}
        _hhr2 = getattr(result, "hh_result", None)
        if _hhr2 and not getattr(_hhr2, "error", ""):
            for _hr in (getattr(_hhr2, "process_results", []) or []):
                if getattr(_hr, "suspicious", 0) > 0:
                    _pid_hh2[getattr(_hr, "pid", 0)] = _hr

        # 도메인 역조회 맵
        _pcap_pp = getattr(result, "pcap_result", None)
        _ip2dom_pp = getattr(_pcap_pp, "ip_to_domain", {}) or {} if _pcap_pp else {}

        # 의심 경로/확장자 필터
        _SUSP_FRAGS_PP = ("\\temp\\", "\\appdata\\", "\\programdata\\",
                          "\\users\\public\\", "\\windows\\system32\\",
                          "\\windows\\syswow64\\")
        _SUSP_EXTS_PP  = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".tmp"}

        _proc_act_lines: list[str] = []

        for _pp in new_procs[:15]:
            _pp_pid  = getattr(_pp, "pid", 0)
            _pp_name = getattr(_pp, "name", "?")

            _fevs  = _pid_fevs.get(_pp_pid, [])
            _revs  = _pid_revs.get(_pp_pid, [])
            _nets  = _pid_nets.get(_pp_pid, [])
            _dnsl  = _pid_dns.get(_pp_pid, [])
            _hh_r  = _pid_hh2.get(_pp_pid)

            if not (_fevs or _revs or _nets or _dnsl or _hh_r):
                continue

            _proc_act_lines.append(f"### {_pp_name} (PID {_pp_pid})")

            # 파일 행위 (의심 경로/확장자 우선, 중복 제거)
            _seen_paths: set[str] = set()
            _flines: list[str] = []
            for _ev in _fevs:
                _op   = getattr(_ev, "operation", "")
                _path = getattr(_ev, "path", "")
                _low  = _path.lower()
                _ext  = ("." + _low.rsplit(".", 1)[-1]) if "." in _low else ""
                if _path in _seen_paths:
                    continue
                if any(f in _low for f in _SUSP_FRAGS_PP) or _ext in _SUSP_EXTS_PP:
                    _seen_paths.add(_path)
                    _tag = "Write" if "Write" in _op else ("Create" if "Create" in _op else "Delete")
                    _flines.append(f"  파일[{_tag}]: {_trunc(_path, 90)}")
            for _fl in _flines[:5]:
                _proc_act_lines.append(_fl)

            # 레지스트리 쓰기 (중복 제거)
            _seen_regs: set[str] = set()
            _rlines: list[str] = []
            for _ev in _revs:
                _path = getattr(_ev, "path", "")
                if _path not in _seen_regs:
                    _seen_regs.add(_path)
                    _rlines.append(f"  레지스트리[Set]: {_trunc(_path, 90)}")
            for _rl in _rlines[:3]:
                _proc_act_lines.append(_rl)

            # 네트워크 연결
            for _pnc in _nets[:4]:
                _rip   = getattr(_pnc, "remote_ip", "")
                _rport = getattr(_pnc, "remote_port", 0)
                _proto = getattr(_pnc, "proto", "TCP")
                _dir   = str(getattr(_pnc, "direction", "")).lower()
                _doms  = _ip2dom_pp.get(_rip, [])
                _host  = f"{_doms[0]}({_rip})" if _doms else _rip
                _arrow = "→" if "out" in _dir else "↔"
                _proc_act_lines.append(f"  네트워크: {_proto}{_arrow}{_host}:{_rport}")

            # DNS 쿼리
            for _dq in _dnsl[:3]:
                _dom = getattr(_dq, "name", "")
                _ans = getattr(_dq, "answers", [])
                _proc_act_lines.append(f"  DNS: {_dom}→{_ans[0] if _ans else '?'}")

            # hollows-hunter 인젝션 탐지
            if _hh_r:
                _repl  = getattr(_hh_r, "replaced", 0)
                _shc   = getattr(_hh_r, "implanted_shc", 0)
                _pe_inj = getattr(_hh_r, "implanted_pe", 0)
                _iparts = []
                if _repl:   _iparts.append(f"코드교체={_repl}")
                if _shc:    _iparts.append(f"쉘코드={_shc}")
                if _pe_inj: _iparts.append(f"PE인젝션={_pe_inj}")
                _proc_act_lines.append(
                    f"  ⚠ 인젝션: {', '.join(_iparts) if _iparts else '의심항목탐지'}"
                )

        if _proc_act_lines:
            lines.append("## 프로세스별 악성 행위 ← 각 프로세스가 실제로 한 행위 (C2·파일·레지 직접 인용)")
            lines.extend(_proc_act_lines)
            lines.append("")

    # ── 지속성/실행 아티팩트 ─────────────────────────────────────────────
    # schtasks, sc, reg 등의 전체 명령줄을 별도 섹션으로 표시
    # → AI가 /tn, /tr, /sc 등 지속성 파라미터를 직접 인용할 수 있도록
    _PERSIST_NAMES = frozenset({
        "schtasks.exe", "sc.exe", "reg.exe", "at.exe",
        "regsvr32.exe", "mshta.exe",
    })
    persist_procs = [
        p for p in new_procs
        if getattr(p, "name", "").lower() in _PERSIST_NAMES
    ]
    if persist_procs:
        lines.append(f"## 지속성/실행 아티팩트 ({len(persist_procs)}건)")
        for p in persist_procs:
            pname = getattr(p, "name", "?")
            ppid  = getattr(p, "pid", "?")
            cmd   = " ".join(getattr(p, "cmdline", []) or []) or getattr(p, "exe", "")
            lines.append(f"- {pname} (PID {ppid}): {_trunc(cmd, 220)}")
        lines.append("")

    # pe-sieve / hollows-hunter 인젝션
    pe_list = getattr(result, "pe_sieve_results", []) or []
    pe_susp = [r for r in pe_list if not getattr(r, "error", "") and getattr(r, "suspicious", 0) > 0]
    hh_r = getattr(result, "hh_result", None)
    hh_proc_results = []
    if hh_r and not getattr(hh_r, "error", ""):
        hh_proc_results = [
            r for r in (getattr(hh_r, "process_results", []) or [])
            if getattr(r, "suspicious", 0) > 0
        ]

    # ── 패커 / 인스톨러 식별 ─────────────────────────────────────────────
    # "추정 악성코드 패밀리" 대신 "NSIS 로 패킹된 드로퍼" 를 쓸 수 있게 하는
    # 확정 사실. 모델은 파일 목록만 보고 이걸 알아내지 못한다.
    _pk = getattr(result, "packer_findings", None) or []
    if _pk:
        lines.append("## 패커 / 인스톨러 식별 ← 확정 사실, 분석 분류와 요약에 반영할 것")
        for p in _pk[:4]:
            lines.append(
                f"- [{p['confidence']}] {p['name']} — {p['description']}"
            )
            for e in (p.get("evidence") or [])[:3]:
                lines.append(f"    근거: {_trunc(e, 100)}")
        lines.append("")

    # ── 정상 구성요소 사칭 ───────────────────────────────────────────────
    _mq = getattr(result, "masquerade_findings", None) or []
    if _mq:
        lines.append("## 정상 구성요소 사칭 탐지 ← 핵심 수법, 요약에 반드시 포함할 것")
        for m in _mq[:6]:
            lines.append(
                f"- [{m['confidence']}] {_trunc(m['path'], 100)} "
                f"({m['technique']}) — {m['reason']}"
            )
        lines.append("")

    # ── YARA ─────────────────────────────────────────────────────────────
    _yr = getattr(result, "yara_result", None)
    if _yr is not None and getattr(_yr, "available", False) and getattr(_yr, "matches", None):
        _ms = _yr.matches
        lines.append(f"## YARA 룰 매치 ({len(_ms)}건) ← 패밀리 판정 1차 근거")
        _seen_rule: set = set()
        for m in _ms[:12]:
            rn = getattr(m, "rule_name", "")
            if rn in _seen_rule:
                continue
            _seen_rule.add(rn)
            _desc = ""
            try:
                _desc = (getattr(m, "meta", {}) or {}).get("description", "") or ""
            except Exception:
                _desc = ""
            _tags = ", ".join(getattr(m, "tags", []) or [])
            lines.append(
                f"- {rn}"
                + (f" [{_tags}]" if _tags else "")
                + f" ← {Path(getattr(m, 'file_scanned', '')).name}"
                + (f" — {_trunc(_desc, 80)}" if _desc else "")
            )
        lines.append("")

    # ── VirusTotal ───────────────────────────────────────────────────────
    _vt_techs = []
    _br_vt = getattr(result, "behavior_report", None)
    for _t in (getattr(_br_vt, "techniques", None) or []):
        _s = [x.upper() for x in (getattr(_t, "sources", None) or [])]
        if "VIRUSTOTAL" in _s:
            _vt_techs.append(_t)
    if _vt_techs:
        lines.append(
            f"## VirusTotal 샌드박스 기여 기법 ({len(_vt_techs)}건) "
            f"← 타 샌드박스 관측 결과, 이번 실행에서 미관측일 수 있음"
        )
        for _t in _vt_techs[:12]:
            lines.append(f"- [{_t.technique_id}] {_t.technique_name} ({_t.tactic})")
        lines.append("")

    # ── DLL 사이드로딩 ───────────────────────────────────────────────────
    _sl = getattr(result, "sideload_findings", None) or []
    if _sl:
        lines.append("## DLL 사이드로딩 탐지 ← 확정 근거, 실행 흐름에 반드시 포함할 것")
        lines.append(
            "정상 실행 파일이 같은 디렉터리의 악성 DLL 을 로드하는 기법입니다. "
            "Windows DLL 검색 순서상 실행 파일 디렉터리가 System32 보다 우선합니다."
        )
        for f in _sl[:6]:
            _comp = f.get("companions") or []
            _cs = ""
            if _comp:
                _cs = " / 동반 파일: " + ", ".join(_trunc(c, 60) for c in _comp[:3])
            lines.append(
                f"- [{f.get('confidence','')}] {f.get('loader_name','')}"
                f"(PID {f.get('loader_pid',0)}) → {_trunc(f.get('dll_path',''), 90)}"
                + ("  (DLL 분석 중 드롭됨)" if f.get("dll_dropped") else "")
                + ("  (동일 디렉터리)" if f.get("same_dir") else "")
                + _cs
            )
        lines.append(
            "동반 파일(.pmt/.dat/.bin 등)은 DLL 이 읽어 복호화하는 암호화 페이로드일 "
            "가능성이 높습니다. 확인된 경우 실행 흐름에 명시하십시오."
        )
        lines.append("")

    # 신뢰도 판정 결과가 있으면 원시 목록 대신 그것을 넣는다.
    # 오탐(LOW)까지 그대로 주면 모델이 dwm.exe·explorer.exe 주입을
    # 확정 사실처럼 서술한다.
    _inj_cls = getattr(result, "injection_findings", None) or []
    if _inj_cls:
        _hi_m = [f for f in _inj_cls if f["confidence"] in ("HIGH", "MEDIUM")]
        _lo_m = [f for f in _inj_cls if f["confidence"] == "LOW"]
        lines.append("## 메모리 인젝션 탐지 (신뢰도 판정 완료)")
        if _hi_m:
            for f in _hi_m[:8]:
                lines.append(
                    f"- [{f['confidence']}] {f['name']}(PID {f['pid']}) "
                    f"쉘코드 {f['implanted_shc']} / PE주입 {f['implanted_pe']} / "
                    f"교체 {f['replaced']} [{f['source']}] — {f['reason']}"
                )
        else:
            lines.append("- 신뢰할 수 있는 주입 탐지 없음")
        if _lo_m:
            lines.append(
                f"- 오탐 추정 {len(_lo_m)}건 제외: "
                + ", ".join(f"{f['name']}(PID {f['pid']})" for f in _lo_m[:5])
                + f" — {_lo_m[0]['reason']}"
            )
        lines.append(
            "**LOW 로 분류된 항목은 서술하지 마십시오.** HIGH 만 확정 주입으로 "
            "기술하고, MEDIUM 은 '주입 의심(미확인)' 으로만 쓰십시오."
        )
        lines.append("")
    elif pe_susp or hh_proc_results:
        lines.append("## 메모리 인젝션 탐지")
        # 이 스캐너들은 정상 프로세스의 .NET JIT·ASLR 재배치 영역을 자주
        # 오탐한다(dwm/explorer/svchost 등). 모델이 이를 확정 사실로 서술하지
        # 않도록 신뢰도 한계를 프롬프트에 명시한다.
        lines.append(
            "주의: hollows-hunter / pe-sieve 는 정상 Windows 프로세스(dwm.exe, "
            "explorer.exe, svchost.exe, SearchApp.exe 등)의 JIT·ASLR 영역을 "
            "오탐하는 경우가 많습니다. 샘플 계보 프로세스가 아닌 탐지는 "
            "'주입 의심(미확인)' 으로만 기술하고, 확정 주입으로 단정하지 마십시오."
        )
        if hh_proc_results:
            total_shc = sum(getattr(r, "implanted_shc", 0) for r in hh_proc_results)
            total_pe  = sum(getattr(r, "implanted_pe", 0) for r in hh_proc_results)
            lines.append(
                f"hollows-hunter 요약: {len(hh_proc_results)}개 프로세스 의심, "
                f"쉘코드 총 {total_shc}개, PE인젝션 총 {total_pe}개"
            )
        for r in pe_susp[:6]:
            name   = getattr(r, "name", "")
            shc    = getattr(r, "implanted_shc", 0)
            pe_inj = getattr(r, "implanted_pe", 0)
            mods   = getattr(r, "modules", []) or []
            mod_names = [Path(m.module_path).name for m in mods if getattr(m, "module_path", "")]
            mod_str = f" ({', '.join(mod_names[:3])})" if mod_names else ""
            lines.append(
                f"- [pe-sieve] PID {r.pid} {name}: 쉘코드 {shc}개, PE인젝션 {pe_inj}개{mod_str}"
            )
        for r in hh_proc_results[:8]:
            shc    = getattr(r, "implanted_shc", 0)
            pe_inj = getattr(r, "implanted_pe", 0)
            name   = getattr(r, "name", "")
            lines.append(
                f"- [hollows-hunter] PID {r.pid} {name}: 쉘코드 {shc}개, PE인젝션 {pe_inj}개"
            )
        lines.append("")

    # ── 파일 시스템 활동 ─────────────────────────────────────────────────
    _FILE_OPS_SHOW = {"WriteFile", "CreateFile", "RenameFile", "DeleteFile"}
    try:
        from parsers.procmon_csv import EventCategory
        file_evs = [
            e for e in (result.filtered_events or [])
            if e.category == EventCategory.FILE
            and e.operation in _FILE_OPS_SHOW
            and e.result == "SUCCESS"
        ]
        # (pid, op, path) 기준 중복 제거
        seen_fe: set = set()
        uniq_fe = []
        for e in file_evs:
            key = (e.pid, e.operation, e.path.lower())
            if key not in seen_fe:
                seen_fe.add(key)
                uniq_fe.append(e)

        if uniq_fe:
            lines.append(f"## 파일 시스템 활동 ({len(uniq_fe)}건 고유)")
            op_label = {
                "WriteFile": "Write", "CreateFile": "Create",
                "RenameFile": "Rename", "DeleteFile": "Delete",
            }
            for e in uniq_fe[:20]:
                detail = ""
                if e.operation == "RenameFile":
                    m = _RENAME_DEST_RE.search(e.detail or "")
                    detail = f" → {_trunc(m.group(1).strip(), 80)}" if m else ""
                elif e.operation == "CreateFile" and "OpenResult: Created" in (e.detail or ""):
                    detail = " [신규생성]"
                lines.append(
                    f"- [{op_label.get(e.operation, e.operation)}] "
                    f"{e.process}({e.pid}) → {_trunc(e.path, 100)}{detail}"
                )
            lines.append("")
    except Exception:
        pass

    # IOC 드롭 파일
    ioc = result.ioc_report
    if ioc and ioc.dropped_files:
        _drops   = _paths_by_tier(ioc, max_tier=2, limit=20)
        _dtiers  = getattr(ioc, "dropped_file_tiers", None) or {}
        _total   = len(ioc.dropped_files)
        _hidden  = _total - len(_drops)
        lines.append(
            f"## 드롭/생성 파일 (관련 {len(_drops)}개 / 전체 {_total}개)"
        )
        if _hidden > 0:
            lines.append(
                f"환경 배경(Windows Update·Defender 등) {_hidden}개는 제외했습니다."
            )
        for f in _drops:
            _mk = {1: "[계보] ", 2: "[의심] "}.get(_dtiers.get(f, 2), "")
            lines.append(f"- {_mk}{_trunc(f, 120)}")
        lines.append("")

    # ── 레지스트리 활동 ──────────────────────────────────────────────────
    _REG_OPS_SHOW = {"RegSetValue", "RegCreateKey", "RegDeleteValue", "RegDeleteKey"}
    try:
        from parsers.procmon_csv import EventCategory
        reg_evs = [
            e for e in (result.filtered_events or [])
            if e.category == EventCategory.REGISTRY
            and e.operation in _REG_OPS_SHOW
            and e.result == "SUCCESS"
        ]
        seen_re: set = set()
        uniq_re = []
        for e in reg_evs:
            key = (e.operation, e.path.lower())
            if key not in seen_re:
                seen_re.add(key)
                uniq_re.append(e)

        if uniq_re:
            lines.append(f"## 레지스트리 활동 ({len(uniq_re)}건 고유)")
            for e in uniq_re[:15]:
                detail_str = _trunc(e.detail or "", 60)
                lines.append(
                    f"- [{e.operation}] {_trunc(e.path, 100)}"
                    + (f"  ({detail_str})" if detail_str else "")
                )
            lines.append("")
    except Exception:
        pass

    # Regshot diff
    reg_diff = result.registry_diff or {}
    added_reg   = reg_diff.get("added",    [])
    modified_reg = reg_diff.get("modified", [])
    if added_reg or modified_reg:
        lines.append(f"## 레지스트리 스냅샷 diff (추가 {len(added_reg)}건 / 변경 {len(modified_reg)}건)")
        for entry in added_reg[:10]:
            k = _trunc(entry[0], 80)
            n = entry[1] if len(entry) > 1 else ""
            v = _trunc(str(entry[2]), 50) if len(entry) > 2 else ""
            lines.append(f"- [추가] {k}\\{n} = {v}")
        for entry in modified_reg[:5]:
            k  = _trunc(entry[0], 80)
            n  = entry[1] if len(entry) > 1 else ""
            nw = _trunc(str(entry[3]), 50) if len(entry) > 3 else ""
            lines.append(f"- [변경] {k}\\{n} → {nw}")
        lines.append("")

    if ioc and ioc.registry_keys:
        lines.append(f"## 레지스트리 IOC ({len(ioc.registry_keys)}개)")
        for r in ioc.registry_keys[:10]:
            lines.append(f"- {_trunc(r, 120)}")
        lines.append("")

    # ── 네트워크 통신 ───────────────────────────────────────────────────
    net_lines: list[str] = []
    pcap = result.pcap_result

    # 프로세스 ↔ IP 매핑 (pnmap)
    pnmap = getattr(result, "process_network_map", []) or []
    ip_proc: dict[str, list[str]] = {}
    for pn in pnmap:
        lbl = f"{pn.process}({pn.pid})"
        lst = ip_proc.setdefault(pn.remote_ip, [])
        if lbl not in lst:
            lst.append(lbl)

    if pcap:
        conns = getattr(pcap, "connections", []) or []
        ext_conns = [c for c in conns if not _is_private_ip(c.dst_ip)]
        if ext_conns:
            # 배경(Tier 3) 제외 + 계보 우선 정렬 — 수백 건 중 앞 15건만 넣으면
            # OS 업데이트 트래픽이 자리를 다 차지하고 C2 는 프롬프트에 못 들어간다.
            _rel_conns = _tier_filtered(ext_conns, max_tier=2)
            _bg_cnt    = len(ext_conns) - len(_rel_conns)
            net_lines.append(
                f"### 외부 연결 (관련 {len(_rel_conns)}건 / 전체 {len(ext_conns)}건"
                + (f", 배경 {_bg_cnt}건 제외" if _bg_cnt > 0 else "") + ")"
            )
            for c in _rel_conns[:15]:
                procs   = ip_proc.get(c.dst_ip, [])
                proc_str = f" [{', '.join(procs[:2])}]" if procs else ""
                net_lines.append(
                    f"- {_tier_mark(c)}{c.proto} {c.dst_ip}:{c.dst_port} "
                    f"송신 {_fmt_bytes(c.bytes_out)}{proc_str}"
                )

        tls_list = getattr(pcap, "tls_info", []) or []
        if tls_list:
            seen_tls: set = set()
            net_lines.append("### TLS SNI")
            for t in tls_list:
                k = (getattr(t, "sni", ""), t.dst_ip)
                if k in seen_tls:
                    continue
                seen_tls.add(k)
                sni     = getattr(t, "sni", "")
                ja3_lbl = getattr(t, "ja3_label", "")
                ja3_hash = getattr(t, "ja3", "")
                tls_ver  = getattr(t, "tls_version", "")
                ja3_str  = (f" [JA3:{ja3_lbl}]" if ja3_lbl
                            else (f" [JA3:{ja3_hash[:12]}]" if ja3_hash else ""))
                net_lines.append(f"- {sni} → {t.dst_ip}:{t.dst_port} {tls_ver}{ja3_str}")
                if len(seen_tls) >= 12:
                    break

        dns_q        = getattr(pcap, "dns_queries", []) or []
        dns_attr     = getattr(result, "dns_attributed", []) or []
        dns_attr_ok  = [q for q in dns_attr if q.attributed]

        if dns_attr_ok or dns_q:
            total_dns = len(dns_attr) if dns_attr else len(dns_q)
            attr_cnt  = len(dns_attr_ok)
            net_lines.append(
                f"### DNS 쿼리 ({total_dns}건"
                + (f", 프로세스 귀속 {attr_cnt}건" if attr_cnt else "")
                + ")"
            )
            if dns_attr_ok:
                # 프로세스별로 그룹화해서 표시
                seen_names: set[str] = set()
                for q in dns_attr_ok[:20]:
                    rips = ", ".join(q.answers[:2]) if q.answers else ""
                    proc = f"{q.process}({q.pid})" if q.pid else q.process
                    threat_lbl = _DOMAIN_THREAT_LABELS.get(q.name.lower(), "")
                    net_lines.append(
                        f"- [{proc}] {_trunc(q.name, 65)}"
                        + (f" → {rips}" if rips else " → DNS응답없음(차단추정)")
                        + (f" {threat_lbl}" if threat_lbl else "")
                    )
                    seen_names.add(q.name)
                # 귀속 실패 건 (미상 프로세스)
                unattr = [q for q in dns_attr if not q.attributed]
                if unattr:
                    unattr_parts = []
                    for q in unattr[:5]:
                        threat_lbl = _DOMAIN_THREAT_LABELS.get(
                            getattr(q, "name", "").lower(), ""
                        )
                        unattr_parts.append(
                            _trunc(q.name, 30) + (f" {threat_lbl}" if threat_lbl else "")
                        )
                    net_lines.append(
                        f"- [프로세스 미상 {len(unattr)}건] " + " ".join(unattr_parts)
                    )
            else:
                # ProcMon 없거나 귀속 실패 — 기존 방식
                for q in dns_q[:15]:
                    name = getattr(q, "name", str(q))
                    rips = ", ".join(getattr(q, "response_ips", [])[:2])
                    threat_lbl = _DOMAIN_THREAT_LABELS.get(name.lower(), "")
                    net_lines.append(
                        f"- {_trunc(name, 70)}"
                        + (f" → {rips}" if rips else "")
                        + (f" {threat_lbl}" if threat_lbl else "")
                    )

        http = _tier_filtered(getattr(pcap, "http_requests", []) or [], max_tier=2)
        _http_all = len(getattr(pcap, "http_requests", []) or [])
        if http:
            net_lines.append(
                f"### HTTP 요청 (관련 {len(http)}건 / 전체 {_http_all}건)"
            )
            for h in http[:15]:
                method   = getattr(h, "method", "")
                host     = getattr(h, "host", "")
                path     = getattr(h, "path", "/")
                ua       = getattr(h, "user_agent", "")
                dst_ip   = getattr(h, "dst_ip", "")
                body_len = getattr(h, "content_length", 0)
                # 프로세스 귀속: dst_ip → pnmap 역조회
                h_procs  = ip_proc.get(dst_ip, [])
                proc_str = f" [{', '.join(h_procs[:2])}]" if h_procs else ""
                ua_str   = f" UA:{_trunc(ua, 35)}" if ua else ""
                # POST body 크기 표시 (C2 유출 크기 파악)
                body_str = f" body:{_fmt_bytes(body_len)}" if (method == "POST" and body_len) else ""
                net_lines.append(
                    f"- {method} http://{host}{_trunc(path, 120)}"
                    f"{body_str}{ua_str}{proc_str}"
                )

        smtp_sessions = getattr(pcap, "smtp_sessions", []) or []
        if smtp_sessions:
            _ip2dom = getattr(pcap, "ip_to_domain", {}) or {}
            net_lines.append(f"### SMTP C2 ({len(smtp_sessions)}건) ← 데이터 유출 주요 채널")
            for s in smtp_sessions[:4]:
                _doms  = _ip2dom.get(s.dst_ip, [])
                _host  = _doms[0] if _doms else s.dst_ip
                _auth  = f" AUTH:{s.auth_user}" if s.auth_user else (" AUTH:확인됨" if s.has_auth else "")
                _ehlo  = f" EHLO:{s.ehlo_domain}" if s.ehlo_domain else ""
                net_lines.append(
                    f"- {_host} ({s.dst_ip}):{s.dst_port}{_ehlo}"
                    f" FROM:{s.mail_from or '-'}"
                    f" TO:{', '.join(s.rcpt_to[:2]) or '-'}"
                    f"{_auth}"
                    + (" [DATA전송완료]" if s.has_data else "")
                )

        ftp_sessions = getattr(pcap, "ftp_sessions", []) or []
        if ftp_sessions:
            net_lines.append(f"### FTP C2 ({len(ftp_sessions)}건)")
            for s in ftp_sessions[:4]:
                net_lines.append(
                    f"- {s.dst_ip}:{s.dst_port} user:{s.username or '-'}"
                    + (f" upload:{', '.join(s.uploaded[:2])}" if s.uploaded else "")
                )

    # HTTPS 복호화
    dr = getattr(result, "decrypted_requests", []) or []
    if dr:
        net_lines.append(f"### HTTPS 복호화 ({len(dr)}건)")
        for req in dr[:8]:
            host   = getattr(req, "host", "")
            method = getattr(req, "method", "")
            path   = getattr(req, "path", "")
            ua     = getattr(req, "user_agent", "")
            status = str(getattr(req, "resp_status", "") or "")
            net_lines.append(
                f"- {method} https://{host}{_trunc(path, 50)}"
                + (f" → HTTP {status}" if status else "")
                + (f" (UA: {_trunc(ua, 40)})" if ua else "")
            )

    # FakeNet-NG
    fn = getattr(result, "fakenet_result", {}) or {}
    fn_dns  = fn.get("dns_queries",   []) or []
    fn_http = fn.get("http_requests", []) or []
    if fn_dns:
        net_lines.append(f"### FakeNet-NG DNS ({len(fn_dns)}건)")
        for d in fn_dns[:10]:
            net_lines.append(f"- {d.get('domain','')}")
    if fn_http:
        net_lines.append(f"### FakeNet-NG HTTP ({len(fn_http)}건)")
        for h in fn_http[:8]:
            net_lines.append(
                f"- [{h.get('proto','')}] {h.get('method','')} "
                f"{h.get('host','')}{_trunc(h.get('path',''), 50)}"
            )

    # IOC 네트워크
    if ioc:
        if ioc.ip_addresses:
            net_lines.append(f"### 외부 IP IOC ({len(ioc.ip_addresses)}개)")
            net_lines += [f"- {ip}" for ip in ioc.ip_addresses[:10]]
        if ioc.domains:
            net_lines.append(f"### 도메인 IOC ({len(ioc.domains)}개)")
            net_lines += [f"- {d}" for d in ioc.domains[:10]]
        if ioc.urls:
            net_lines.append(f"### URL IOC ({len(ioc.urls)}개)")
            net_lines += [f"- {_trunc(u, 100)}" for u in ioc.urls[:8]]
        if ioc.mutexes:
            net_lines.append(f"### Mutex ({len(ioc.mutexes)}개)")
            net_lines += [f"- {m}" for m in ioc.mutexes[:6]]

    if net_lines:
        lines.append("## 네트워크 통신")
        lines.extend(net_lines)
        # 배경으로 판정된 도메인을 명시해 C2 오지목을 막는다
        lines.extend(_background_summary(result))
        lines.append("")

    # ── 메모리 포렌식 (Volatility) ───────────────────────────────────────
    mf = getattr(result, "mem_forensics", {}) or {}
    if mf and not mf.get("error"):
        malfind = mf.get("malfind", []) or []
        handles = mf.get("handles", []) or []
        mutants = [h for h in handles if h.get("type") == "Mutant"]
        netscan = mf.get("netscan", []) or []
        if malfind or mutants or netscan:
            lines.append("## 메모리 포렌식 (Volatility)")
            if malfind:
                lines.append(f"### malfind ({len(malfind)}건)")
                for m in malfind[:5]:
                    prot = m.get("protection", "")
                    lines.append(
                        f"- PID {m.get('pid')} {m.get('process')} "
                        f"@ {m.get('start_vpn','?')} [{prot}]"
                    )
            if mutants:
                lines.append(f"### Mutex (Mutant {len(mutants)}개)")
                for h in mutants[:6]:
                    lines.append(f"- {h.get('handle_name','')}")
            if netscan:
                lines.append(f"### netscan ({len(netscan)}건)")
                for n in netscan[:6]:
                    if not _is_private_ip((n.get("foreign", ":0") + ":").split(":")[0]):
                        lines.append(
                            f"- {n.get('proto','')} {n.get('local','')} → "
                            f"{n.get('foreign','')} [{n.get('state','')}] {n.get('owner','')}"
                        )
            lines.append("")

    # ── 사전 계산 태그 힌트 ─────────────────────────────────────────────
    computed_tags = _compute_tags(result)
    tag_hint = ""
    if computed_tags:
        tag_hint = "\n".join(f"  {tag}: {reason}" for tag, reason in computed_tags)

    # ── 분석 지시 ───────────────────────────────────────────────────────
    # 아래 템플릿을 LLM이 그대로 채워 넣도록 지시
    template = """---
당신의 역할은 위 데이터를 **읽히는 분석 서술로 옮기는 것**입니다.
탐지는 이미 끝났습니다. 없는 사실을 만들어내지 말고, 있는 사실을 연결하십시오.

[출력 형식]
- 아래 섹션 제목과 필드 이름을 그대로 쓰고, 대괄호 [ ] 안 내용만 교체하세요.
- 순수 텍스트로만 출력하세요. 마크다운(##, **, -, ``` 등) 금지.
- 대응 권고·조치 방안은 쓰지 마세요.
- 기법 ID(T1055 등)는 "마이터 기법 목록" 에만 쓰세요. 나머지 섹션에서는
  "T1055" 가 아니라 "explorer.exe 에 쉘코드 주입" 처럼 행위로 쓰십시오.
  ID 나열은 읽는 사람에게 아무 정보도 주지 않습니다.

[데이터 신뢰 순서 — 충돌하면 위쪽을 따르십시오]
1. "확정 근거" 표시가 붙은 섹션 (DLL 사이드로딩, 사칭 탐지, 패커 식별)
   → 이미 검증된 사실입니다. 반드시 서술에 반영하십시오.
2. 프로세스 실행 체인 · 파일 · 레지스트리 · 네트워크 관측 데이터
3. YARA 매치 → 패밀리 판정 근거로 사용 가능
4. VirusTotal 기여 기법 → 타 샌드박스 관측. 이번 실행 결과가 아님
5. CAPA 기법 → 바이너리 정적 분석. "코드가 있다" 일 뿐 "실행했다" 가 아님

[정적 분석과 동적 관측을 혼동하지 마십시오]
- CAPA·VirusTotal 유래 기법을 관측된 행위처럼 쓰면 안 됩니다.
  틀린 예: "지속성 기법으로 자동 실행을 등록했습니다"
  맞는 예: "레지스트리 수정 코드가 존재하나 이번 실행에서는 관측되지 않았습니다"
- 관측 데이터와 어긋나면 언제나 관측을 따르십시오.

[증거 등급]
HIGH   파일명·경로·IP·도메인·프로세스명이 데이터에 직접 있음 → 사실로 기술
MEDIUM 행위 패턴으로 추론 가능 → 반드시 "추정" 표기
LOW    데이터에 없음 → 기술 금지

[없으면 없다고 쓰십시오 — 가장 중요]
- 기본값은 "관측되지 않음" 입니다. 빈칸을 채우려고 추측하지 마십시오.
- 관측된 행위가 적다는 것 자체가 유효한 분석 결과입니다.
  샌드박스 탐지 코드가 있는데 행위가 없으면 "분석 환경을 탐지해 실행을
  중단했을 가능성" 을 언급하는 편이 억지 서술보다 낫습니다.
- "자격증명 수집", "키로깅", "스크린샷" 은 직접 증거가 있을 때만 쓰십시오.
- "다수의 IP", "시스템 도구", "악성 서버" 같은 추상 표현 금지. 실제 값을 쓰십시오.

{tag_section}

분석 분류
위협 수준: [악성 활동 / 의심 활동 / 정상 중 하나만 선택]
주요 분석 대상: {sample_name} ([실행 경로와 실행 방식. "분석 대상" 섹션의 실제 경로만 사용])
패커 / 빌드: [패커·인스톨러 식별 결과를 그대로 기재. 없으면 "미식별"]
설명: [한 문장. 유형(드로퍼/로더/스틸러 등)과 핵심 기능. YARA 매치가 있으면 룰 이름을 패밀리 근거로 인용. C2 가 관측된 경우에만 도메인/IP 포함, 아니면 언급하지 말 것.]
태그 및 해석:
[탐지된 태그 이름]: [한 문장. 실제 파일명·경로·프로세스명 인용. 기법 ID 금지.]

핵심 요약
[2~3문장. 이 샘플이 실제로 무엇을 했는지 행위로 서술.
 확정 근거 섹션(사이드로딩·사칭·패커)이 있으면 반드시 반영하십시오.
 좋은 예: "NSIS 로 패킹된 드로퍼로, ProgramData 하위에 정상 구성요소를 사칭한
 이름의 실행 파일과 DLL 을 떨구고 자식 프로세스로 실행해 DLL 을 사이드로드했다."
 나쁜 예: "T1055, T1027 기법이 사용되었습니다." (정보 없음)]

실행 흐름
[프로세스 실행 체인을 부모→자식 순서로 재구성. 각 단계에 실제 파일 경로와
 프로세스명을 넣으십시오. 단계가 3개보다 적으면 있는 만큼만 쓰고 억지로 채우지 마십시오.
 분석 도구(python.exe, procmon 등)의 동작은 공격 단계가 아닙니다.]
[1단계] [진입점 — 샘플 실행과 최초 전개(임시 디렉터리 추출 등)]
[2단계] [준비 — 드롭 경로, 파일명, 자식 프로세스 생성]
[3단계] [실행 — 사이드로딩·주입·네트워크 통신. 관측되지 않았으면 "관측되지 않음"]

결론
[1~2문장. 최종 위협 판단과 공격자 의도. 관측 근거에 한정. 기법 ID 금지.]

마이터 기법 목록
[위 "MITRE ATT&CK" 목록에 **없는** 기법 중, 관측 데이터에 직접 근거가 있는 것만
 추가로 나열하십시오. 이미 목록에 있는 기법을 다시 쓰지 마십시오 — 중복입니다.
형식: T기법ID|기법명(영문)|전술명(영문)|구체적 근거(파일명·프로세스·IP 직접 인용)
예시: T1574.002|DLL Side-Loading|Defense Evasion|PushNotifyBroker.exe가 동일 디렉터리 rILrKi.dll 로드
규칙: 기법명과 전술명을 정확히 쓰십시오. 모르면 그 줄을 쓰지 마십시오.
      추가할 기법이 없으면 "없음" 한 줄만 작성. 파이프(|) 구분자 유지.]"""

    tag_section = ""
    if tag_hint:
        tag_section = (
            "데이터 기반 탐지 태그 힌트 (태그 및 해석 섹션에 반드시 포함하세요):\n"
            + tag_hint
        )

    lines.append(template.format(
        tag_section=tag_section,
        sample_name=sample_name,
    ))

    prompt = "\n".join(lines)
    # 데이터가 초과되면 중간 데이터를 잘라내되 템플릿(지시)은 항상 보존
    if len(prompt) > max_chars:
        divider = "\n---\n"
        if divider in prompt:
            data_part, instr_part = prompt.split(divider, 1)
            cutoff = max_chars - len(instr_part) - len(divider) - 60
            data_part = data_part[:max(cutoff, 500)]
            prompt = data_part + "\n\n(데이터 초과로 일부 생략됨)" + divider + instr_part
        else:
            prompt = prompt[:max_chars]
    return prompt


# ── Ollama 호출 ───────────────────────────────────────────────────────────────

def _call_ollama(
    prompt:   str,
    base_url: str,
    model:    str,
    timeout:  int,
) -> str:
    """Ollama /api/generate 스트리밍 호출 → 응답 텍스트.

    stream=True 로 토큰을 하나씩 수신하므로 소켓 타임아웃(per-read)에
    영향받지 않아 대형 모델(14b+)에서도 타임아웃이 발생하지 않는다.
    """
    payload = json.dumps({
        "model":  model,
        "prompt": prompt,
        "stream": True,
        "options": {
            "temperature": 0.2,
            "num_ctx":     8192,
            "num_predict": 4096,
        },
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{base_url}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    # timeout: prefill(입력처리) + 생성 전 구간 모두 포함한 소켓 대기
    # CPU 추론 시 prefill이 120s를 초과할 수 있으므로 전체 timeout 적용
    parts: list[str] = []
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw_line in resp:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError:
                    continue
                token = chunk.get("response", "")
                if token:
                    parts.append(token)
                if chunk.get("done"):
                    break
    except TimeoutError:
        if parts:
            # 부분 응답이 있으면 그대로 반환 (타임아웃 주석 추가)
            parts.append("\n\n*(타임아웃으로 분석이 중단되었습니다)*")
        else:
            raise
    return "".join(parts)


# ── NVIDIA NIM 호출 ───────────────────────────────────────────────────────────

_THINK_RE = _re.compile(r"<think>.*?</think>\s*", _re.DOTALL | _re.IGNORECASE)

# reasoning 모델은 사고 과정 토큰도 max_tokens 를 소진한다.
# 기본 4096 이면 답변 시작 전에 잘려 빈 응답이 되므로 상한을 크게 잡는다.
_REASONING_HINTS   = ("deepseek-r1", "qwq", "reasoning", "thinking", "-r1-")
_MAX_TOKENS        = 4096
_MAX_TOKENS_REASON = 16384


def _is_reasoning_model(model: str) -> bool:
    m = (model or "").lower()
    return any(h in m for h in _REASONING_HINTS)


def default_max_tokens(model: str) -> int:
    return _MAX_TOKENS_REASON if _is_reasoning_model(model) else _MAX_TOKENS


def _strip_think(text: str) -> str:
    """reasoning 모델(deepseek-r1 등)의 <think> 블록 제거.

    사고 과정 안에 등장하는 MITRE 기법 ID 를 parse_mitre_from_ai 가
    오탐하는 것을 막는다.
    """
    out = _THINK_RE.sub("", text)
    # 닫히지 않은 <think> (타임아웃으로 스트림 중단 등) → 이후 전부 사고 과정 취급
    if "<think>" in out:
        out = out.split("<think>", 1)[0]
    return out.strip()


def _nvidia_http_error(e: urllib.error.HTTPError) -> str:
    """HTTPError → 사람이 읽을 수 있는 원인 메시지."""
    try:
        body = e.read().decode("utf-8", "replace").strip()[:300]
    except Exception:
        body = ""
    hints = {
        400: "요청이 거부되었습니다 (모델이 지원하지 않는 파라미터일 수 있음)",
        401: f"API 키가 잘못되었거나 만료되었습니다 (환경변수 {NVIDIA_API_KEY_ENV} 확인)",
        402: "무료 크레딧이 소진되었습니다 (build.nvidia.com 에서 잔량 확인)",
        403: "해당 모델에 대한 접근 권한이 없습니다",
        404: ("모델 이름 또는 엔드포인트 경로를 찾을 수 없습니다. "
              "`python analyzer.py --list-ai-models` 로 사용 가능한 모델을 확인하세요"),
        429: "요청 한도 초과(레이트리밋) — 잠시 후 재시도하세요",
    }
    msg = f"NVIDIA API 오류 HTTP {e.code}"
    hint = hints.get(e.code, "")
    if hint:
        msg += f" — {hint}"
    if body:
        msg += f"\n{body}"
    return msg


def _call_nvidia(
    prompt:     str,
    base_url:   str,
    api_key:    str,
    model:      str,
    timeout:    int,
    max_tokens: int = 0,
) -> str:
    """NVIDIA NIM /v1/chat/completions 스트리밍 호출 → 응답 텍스트.

    OpenAI 호환 SSE 형식(`data: {...}` / `data: [DONE]`)을 파싱한다.
    reasoning 모델의 delta.reasoning_content 는 무시하고 content 만 모은다.
    max_tokens 가 0 이면 모델 종류에 맞춰 자동 결정한다.
    """
    max_tokens = max_tokens or default_max_tokens(model)
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": _NVIDIA_SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "temperature": 0.2,
        "top_p":       0.9,
        "max_tokens":  max_tokens,
        "stream":      True,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=payload,
        headers=_nvidia_headers(api_key, stream=True),
        method="POST",
    )

    parts: list[str] = []
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", "replace").strip()
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue
                choices = chunk.get("choices") or []
                if not choices:
                    continue
                token = (choices[0].get("delta") or {}).get("content") or ""
                if token:
                    parts.append(token)
                if choices[0].get("finish_reason"):
                    break
    except urllib.error.HTTPError as e:
        raise RuntimeError(_nvidia_http_error(e)) from None
    except TimeoutError:
        if parts:
            # 부분 응답이 있으면 그대로 반환 (타임아웃 주석 추가)
            parts.append("\n\n*(타임아웃으로 분석이 중단되었습니다)*")
        else:
            raise
    return _strip_think("".join(parts))


# ── 공개 API ─────────────────────────────────────────────────────────────────

class AiAnalyzer:
    """동적 분석 결과 AI 해석기 (NVIDIA NIM / Ollama 공통).

    프롬프트 생성·행위 섹션 주입·MITRE 파싱은 프로바이더와 무관하며,
    HTTP 호출 계층만 provider 에 따라 갈린다.
    """

    def __init__(
        self,
        provider:         str = "ollama",
        base_url:         str = "",
        model:            str = "",
        api_key:          str = "",
        max_prompt_chars: int = 0,
        max_tokens:       int = 0,
    ) -> None:
        provider = (provider or "ollama").lower()
        if provider not in PROVIDERS:
            raise ValueError(f"지원하지 않는 AI 프로바이더: {provider} (가능: {', '.join(PROVIDERS)})")
        self.provider = provider

        if provider == "nvidia":
            self.base_url = (base_url or NVIDIA_BASE_URL).rstrip("/")
            self.model    = model or NVIDIA_DEFAULT_MODEL
        else:
            self.base_url = (base_url or OLLAMA_BASE_URL).rstrip("/")
            self.model    = model or DEFAULT_MODEL

        self.api_key          = api_key or ""
        self.max_prompt_chars = max_prompt_chars or _MAX_PROMPT_CHARS_BY_PROVIDER[provider]
        # 0 이면 _call_nvidia 가 모델 종류(reasoning 여부)에 맞춰 결정
        self.max_tokens       = max_tokens or 0

    @property
    def label(self) -> str:
        return f"{self.provider}/{self.model}"

    def is_available(self) -> bool:
        if self.provider == "nvidia":
            return _is_nvidia_available(self.base_url, self.api_key)
        return _is_ollama_running(self.base_url)

    def model_loaded(self) -> bool:
        if self.provider == "nvidia":
            return _is_nvidia_model_available(self.base_url, self.api_key, self.model)
        return _is_model_available(self.base_url, self.model)

    def analyze(
        self,
        result,
        timeout: int = 600,
    ) -> AiAnalysisResult:
        """AnalysisResult → AiAnalysisResult."""
        ai = AiAnalysisResult(model=self.model, provider=self.provider)

        if not self.is_available():
            ai.error = (
                f"NVIDIA API에 연결할 수 없습니다 ({self.base_url}) — API 키/네트워크를 확인하세요"
                if self.provider == "nvidia"
                else f"Ollama 서버에 연결할 수 없습니다 ({self.base_url})"
            )
            return ai

        prompt = _build_prompt(result, max_chars=self.max_prompt_chars)
        ai.prompt_chars = len(prompt)

        t0 = time.monotonic()
        try:
            if self.provider == "nvidia":
                ai.response = _call_nvidia(
                    prompt, self.base_url, self.api_key, self.model, timeout,
                    max_tokens=self.max_tokens,
                )
            else:
                ai.response = _call_ollama(prompt, self.base_url, self.model, timeout)

            if not ai.response.strip():
                # reasoning 모델이 사고 과정만 내고 max_tokens 를 소진한 경우가 대표적
                ai.error = (
                    "응답이 비어 있습니다"
                    + (" — reasoning 모델이 사고 과정만 출력했을 수 있습니다 "
                       "(config.json ai.nvidia.max_tokens 를 늘리거나 일반 instruct 모델 사용)"
                       if self.provider == "nvidia" and _is_reasoning_model(self.model)
                       else "")
                )
                ai.elapsed_sec = round(time.monotonic() - t0, 1)
                return ai

            # 데이터로 확정 가능한 섹션은 계산값으로 교체 (할루시네이션 방지)
            try:
                _beh = _build_behavioral_text(result)
                ai.response = _inject_behavioral_section(ai.response, _beh)
            except Exception:
                pass
            try:
                # C2 오지목(msftconnecttest.com 등)을 원천 차단
                _ioc_txt = _build_ioc_text(result)
                ai.response = _replace_section(ai.response, "확인된 IOC", _ioc_txt)
            except Exception:
                pass
            try:
                # 서술 섹션의 기법 ID → 기법 이름 (요약의 ID 나열 방지)
                # MITRE 파싱보다 먼저 하면 목록 섹션은 보존되므로 순서 무관
                ai.response = _expand_technique_ids(ai.response, result)
            except Exception:
                pass
            ai.mitre_techniques = parse_mitre_from_ai(ai.response)
        except urllib.error.URLError as e:
            ai.error = f"{self.provider} 연결 오류: {getattr(e, 'reason', e)}"
        except TimeoutError:
            if self.provider == "nvidia":
                ai.error = f"NVIDIA 타임아웃 ({timeout}s) — 네트워크가 느리거나 서버가 혼잡합니다."
            else:
                ai.error = f"Ollama 타임아웃 ({timeout}s) — 모델이 로드되지 않았거나 응답이 느립니다."
        except Exception as e:
            ai.error = str(e)

        ai.elapsed_sec = round(time.monotonic() - t0, 1)
        return ai


class OllamaAnalyzer(AiAnalyzer):
    """하위 호환 래퍼 — 기존 OllamaAnalyzer(base_url=, model=) 호출부를 유지한다."""

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        model:    str = DEFAULT_MODEL,
    ) -> None:
        super().__init__(provider="ollama", base_url=base_url, model=model)


def select_analyzer(
    provider:          str = "auto",
    nvidia_base_url:   str = "",
    nvidia_model:      str = "",
    nvidia_api_key:    str = "",   # 명시값 (CLI --ai-api-key)
    nvidia_cfg_key:    str = "",   # config.json ai.nvidia.api_key (최하위 우선순위)
    nvidia_max_chars:  int = 0,
    nvidia_max_tokens: int = 0,
    ollama_url:        str = "",
    ollama_model:      str = "auto",
    ollama_max_chars:  int = 0,
    model_override:    str = "",
) -> tuple:
    """사용할 프로바이더를 골라 AiAnalyzer 를 만든다.

    provider
        "auto"   NVIDIA 를 먼저 시도하고 실패하면 Ollama 로 폴백 (기본)
        "nvidia" NVIDIA 고정 — 실패 시 폴백 없음
        "ollama" Ollama 고정 — 외부 전송 없음 (격리망용)

    model_override 는 CLI --ai-model 값으로, 선택된 프로바이더에 맞지 않으면
    무시하고 해당 프로바이더의 기본/자동감지 모델을 쓴다.

    반환: (AiAnalyzer | None, 진행 상황 메시지 list[str])
    """
    provider = (provider or "auto").lower()
    notes: list[str] = []

    nvidia_base = (nvidia_base_url or NVIDIA_BASE_URL).rstrip("/")
    ollama_base = (ollama_url or OLLAMA_BASE_URL).rstrip("/")

    if provider not in ("auto",) + PROVIDERS:
        notes.append(f"알 수 없는 프로바이더 '{provider}' → auto 로 진행")
        provider = "auto"

    # ── 1순위: NVIDIA ────────────────────────────────────────────────
    if provider in ("auto", "nvidia"):
        key     = resolve_nvidia_key(nvidia_api_key, nvidia_cfg_key)
        n_model = model_override or nvidia_model or NVIDIA_DEFAULT_MODEL
        if not key:
            notes.append(
                f"NVIDIA: API 키 없음 (환경변수 {NVIDIA_API_KEY_ENV} 또는 "
                f"config.json ai.nvidia.api_key)"
            )
        elif not _is_nvidia_available(nvidia_base, key):
            notes.append(f"NVIDIA: 연결 실패 ({nvidia_base}) — 키 유효성/네트워크 확인")
        elif model_override and _looks_like_ollama_model(model_override):
            # --ai-model 에 Ollama 모델명(qwen2.5:14b)을 준 경우 —
            # NVIDIA 로 강제하지 않고 Ollama 의도로 해석한다.
            notes.append(f"NVIDIA: '{model_override}' 은 Ollama 모델명 형식 → NVIDIA 건너뜀")
        else:
            # 카탈로그에 맞춰 모델을 해석한다. 설정값이 없어졌더라도
            # 404 로 죽지 않고 선호 순위에 따라 자동 대체된다.
            n_model, _note = resolve_nvidia_model(nvidia_base, key, n_model)
            if _note:
                notes.append(f"NVIDIA: {_note}")
            return AiAnalyzer(
                provider="nvidia", base_url=nvidia_base, model=n_model,
                api_key=key, max_prompt_chars=nvidia_max_chars,
                max_tokens=nvidia_max_tokens,
            ), notes

        if provider == "nvidia":
            return None, notes
        notes.append("NVIDIA 사용 불가 → Ollama 폴백")

    # ── 2순위: Ollama ────────────────────────────────────────────────
    if provider in ("auto", "ollama"):
        if not _is_ollama_running(ollama_base):
            notes.append(f"Ollama: 서버 미실행 ({ollama_base})")
            return None, notes

        o_model = model_override or ollama_model or "auto"
        if not o_model or o_model == "auto":
            o_model = detect_model(ollama_base) or ""
        elif not _is_model_available(ollama_base, o_model):
            # 폴백 시 --ai-model 이 NVIDIA 모델명인 경우가 흔하다 → 자동 감지로 대체
            _det = detect_model(ollama_base)
            if _det:
                notes.append(f"Ollama: 모델 '{o_model}' 없음 → '{_det}' 사용")
            o_model = _det or ""
        if not o_model:
            notes.append("Ollama: 설치된 모델 없음 (ollama pull qwen2.5:7b)")
            return None, notes

        return AiAnalyzer(
            provider="ollama", base_url=ollama_base, model=o_model,
            max_prompt_chars=ollama_max_chars,
        ), notes

    return None, notes


def ai_analysis_to_dict(r: AiAnalysisResult) -> dict:
    return {
        "model":            r.model,
        "provider":         r.provider,
        "response":         r.response,
        "elapsed_sec":      r.elapsed_sec,
        "prompt_chars":     r.prompt_chars,
        "error":            r.error,
        "mitre_techniques": r.mitre_techniques,
    }
