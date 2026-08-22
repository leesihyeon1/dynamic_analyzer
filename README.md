# dynamic_analyzer

Windows 악성코드 동적 분석 자동화 도구.  
ProcMon · tshark · pe-sieve · hollows-hunter · CAPA · YARA · Volatility3 · LLM(NVIDIA NIM / Ollama) 을 조합해 **Noriben.py** 스타일로 동작하며,  
실행 한 줄로 샘플 모니터링 → MITRE ATT&CK 매핑 → HTML/JSON 리포트까지 자동 생성합니다.

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **ProcMon 자동화** | 백그라운드 실행 → CSV 변환 → 파싱 |
| **패킷 캡처** | tshark로 pcap 수집, scapy/tshark로 연결/DNS/TLS SNI/HTTP 분석 |
| **외부 PCAP 분석** | `--pcap` 옵션으로 Wireshark 캡처 파일 직접 분석 |
| **scapy 없이 PCAP 분석** | scapy 미설치 시 tshark fallback 파서로 자동 대체 |
| **SMTP/FTP C2 분석** | AgentTesla 류 정보탈취 악성코드의 메일·FTP 탈취 통신 자동 파싱 |
| **TLS 세션 키 복호화** | `SSLKEYLOGFILE` 환경변수로 HTTPS 평문 재구성 (브라우저·curl 등) |
| **FakeNet-NG 연동** | 가짜 DNS/HTTP/TCP 서버로 C2 응답 시뮬레이션, 연결 시도 도메인·URL 수집 |
| **레지스트리 diff** | 실행 전·후 winreg 스냅샷 비교 (Regshot 대체) |
| **프로세스 추적** | psutil로 자식 PID 추적, 신규/종료 프로세스 감지 |
| **실시간 프로세스 감시** | 1초 폴링으로 신규 PID 즉시 pe-sieve 스캔 (타이밍 문제 해소) |
| **pe-sieve / hollows-hunter** | 프로세스 인젝션·PE 할로잉·쉘코드 삽입 탐지, raw dump 자동 추출 |
| **쉘코드 덤프 재분석** | pe-sieve/HH가 덤프한 `.shc`·`.bin` 파일에 YARA + CAPA `--shellcode` 적용, 오탐 필터링 포함 |
| **물리 메모리 덤프** | winpmem / DumpIt으로 RAM 전체 덤프 (`--memdump`) |
| **Volatility3 포렌식** | malfind · pstree · netscan · cmdline · handles · dlllist 병렬 실행, 오류 원인 리포트 포함 |
| **AI 행위 분석** | NVIDIA NIM 우선 → Ollama 폴백 — 악성코드 패밀리 추정 · 위협 수준 · 행위 분석 · C2 패턴 한국어 자동 생성 |
| **CAPA 정적 분석** | 샘플 바이너리에 CAPA 적용 → ATT&CK 기법 자동 추출 |
| **VirusTotal 연동** | SHA256 기반 샌드박스 ATT&CK 기법 조회 (API 키 선택 설정) |
| **프로세스↔네트워크 매핑** | ProcMon TCP/UDP 이벤트 기반, 프로세스별 외부 연결 집계 |
| **노이즈 필터** | 시스템 프로세스 + 분석 도구(ProcMon·tshark·SystemInformer 등) 이벤트 자동 제거 |
| **인젝션 이벤트 표시** | HH/pe-sieve 탐지 인젝션 대상 PID의 파일·레지스트리 이벤트 자동 포함 |
| **MITRE ATT&CK** | 행동 패턴 + CAPA + VirusTotal → 기법 자동 매핑 (T1059, T1547, T1486 등) |
| **IOC 추출** | 외부 IP·도메인·드롭 파일·레지스트리 키·URL (SMTP/FTP C2 IP 포함) |
| **리포트 생성** | 다크 테마 HTML(검색바 + 페이지네이션) + 구조화된 JSON, 분석 완료 후 자동 열기 |
| **Hunt 탭** | abuse.ch 실시간 IOC 조회 — MalwareBazaar · ThreatFox · URLhaus · Feodo Tracker를 HTML 내에서 직접 검색 |
| **VM 자동 세팅** | 스냅샷 복원 후 매 실행 시 캡처 최적화 레지스트리 정책 자동 적용 (Chrome/Edge DoH·QUIC·Firefox DoH·LLMNR·NetBIOS 비활성화) |

---

## 요구사항

### 필수
- **Windows 10/11** (또는 Windows VM)
- **Python 3.10+**
- **관리자 권한** (ProcMon, tshark, winpmem 모두 필요)
- **FLARE VM** 또는 동적 분석 전용 VM 환경 권장

```powershell
pip install -r requirements.txt
```

```
psutil>=5.9.0
scapy>=2.5.0   # 없으면 tshark fallback 파서로 자동 대체
rich>=13.7.0
yara-python    # 선택 — 쉘코드 YARA 스캔
```

### 선택 도구 (자동 감지)

| 도구 | 기본 경로 | 없으면 |
|------|-----------|--------|
| **ProcMon** (`Procmon64.exe`) | `C:\Tools\SysinternalsSuite\` 또는 PATH | ProcMon 기능 스킵 |
| **tshark** (Wireshark 포함) | `C:\Program Files\Wireshark\` 또는 PATH | 패킷 캡처 스킵 |
| **Process Hacker** / **System Informer** | `C:\Tools\processhacker\` | psutil로 대체 |
| **pe-sieve** (`pe-sieve64.exe`) | `C:\Tools\pe-sieve\` 또는 PATH | 인젝션/쉘코드 탐지 스킵 |
| **hollows_hunter** (`hollows_hunter64.exe`) | `C:\Tools\hollows_hunter\` 또는 PATH | 전체 시스템 스캔 스킵 |
| **CAPA** (`capa.exe`) | `C:\Tools\capa\` 또는 PATH | 정적 ATT&CK 분석 스킵 |
| **winpmem** / **DumpIt** | `C:\Tools\winpmem\` 또는 PATH | `--memdump` 사용 불가 |
| **Volatility3** (`vol.py` / `vol3`) | `C:\Tools\volatility3\` 또는 PATH | 메모리 포렌식 스킵 |
| **FakeNet-NG** (`FakeNet.exe`) | PATH 또는 `--fakenet-path` 명시 | FakeNet 기능 스킵 |
| **NVIDIA NIM** (API 키) | 환경변수 `NVIDIA_API_KEY` | Ollama 로 폴백 |
| **Ollama** | `http://localhost:11434` | (NVIDIA도 없으면) AI 분석 스킵 |

---

## 사용법

### 기본 실행

```powershell
# 관리자 PowerShell에서 실행
python analyzer.py malware.exe
```

### 주요 옵션

```powershell
# 모니터링 시간 변경 (기본 60초)
python analyzer.py malware.exe --timeout 120

# 출력 디렉터리 지정
python analyzer.py malware.exe -o C:\results\

# tshark 인터페이스 번호 지정
python analyzer.py malware.exe --interface 2

# ProcMon 또는 tshark 개별 비활성화
python analyzer.py malware.exe --no-procmon
python analyzer.py malware.exe --no-tshark

# 분석 완료 후 HTML 리포트 자동 열기 비활성화
python analyzer.py malware.exe --no-open
```

### 메모리 포렌식 (Volatility3)

```powershell
# 분석 종료 후 물리 메모리 덤프 + Volatility3 실행
# (RAM 크기에 비례한 시간 소요 — 4 GB ≈ 2~5분)
python analyzer.py malware.exe --memdump

# winpmem / Volatility3 경로 직접 지정
python analyzer.py malware.exe --memdump --winpmem-path C:\Tools\winpmem.exe --vol-path C:\Tools\volatility3\vol.py

# 덤프 타임아웃 변경 (기본 600초)
python analyzer.py malware.exe --memdump --dump-timeout 900

# 이미 만들어진 덤프 파일 재사용 (재덤프 없이 Volatility3만 실행)
python analyzer.py malware.exe --memdump --dump C:\dumps\memory.raw
```

> **심볼 파일**: Volatility3는 OS 버전에 맞는 ISF 심볼 파일이 필요합니다.  
> `vol -f memory.raw windows.info` 로 최초 실행 시 자동 다운로드됩니다.

### TLS 복호화 (HTTPS 평문 재구성)

```powershell
# SSLKEYLOGFILE 자동 주입 (Chrome·Edge·Firefox·curl 등)
python analyzer.py malware.exe  # 기본 활성화

# 비활성화
python analyzer.py malware.exe --no-keylog
```

### FakeNet-NG 연동

```powershell
# 가짜 DNS/HTTP/TCP 서버로 C2 응답 시뮬레이션 (tshark 대신)
python analyzer.py malware.exe --fakenet

# FakeNet-NG 경로 명시
python analyzer.py malware.exe --fakenet --fakenet-path C:\Tools\FakeNet\FakeNet.exe
```

### AI 행위 분석 (NVIDIA NIM / Ollama)

기본값은 `--ai-provider auto` — **NVIDIA 를 먼저 시도하고, 키가 없거나 연결에 실패하면 Ollama 로 자동 폴백**합니다.
둘 다 사용할 수 없으면 AI 분석만 건너뛰고 나머지 분석은 그대로 진행됩니다.

AI 분석은 **기본 활성화**이며 `--no-ai` 로 끕니다.

```powershell
# 1) NVIDIA 무료 API 키 설정 (https://build.nvidia.com 에서 발급)
$env:NVIDIA_API_KEY = "nvapi-..."

# 2) 실행 — NVIDIA 우선, 실패 시 Ollama 폴백
python analyzer.py malware.exe

# 프로바이더 고정
python analyzer.py malware.exe --ai-provider nvidia
python analyzer.py malware.exe --ai-provider ollama   # 격리망: 외부 전송 없음

# 모델 지정 (NVIDIA 기본: qwen/qwen2.5-72b-instruct / Ollama 기본: 실행 중인 모델 자동 감지)
python analyzer.py malware.exe --ai-model meta/llama-3.3-70b-instruct
python analyzer.py malware.exe --ai-provider ollama --ai-model qwen2.5:14b

# AI 분석 비활성화
python analyzer.py malware.exe --no-ai
```

> ⚠️ **NVIDIA 사용 시 프롬프트가 외부로 전송됩니다.**
> 프롬프트에는 파일 경로·프로세스명·C2 IP·해시·호스트명이 포함될 수 있습니다.
> 검체 데이터를 외부로 내보낼 수 없는 환경에서는 반드시 `--ai-provider ollama` 를 사용하거나
> `config.json` 의 `ai.provider` 를 `"ollama"` 로 고정하세요.

> **API 키 우선순위**: `--ai-api-key` > 환경변수 `NVIDIA_API_KEY` > `config.json` 의 `ai.nvidia.api_key`
> (설정 파일 평문 저장을 피하려면 환경변수를 쓰세요.)
> 무료 크레딧·레이트리밋 정책은 https://build.nvidia.com 에서 확인하세요.

> **Ollama 설치**: https://ollama.com  
> 모델 다운로드: `ollama pull qwen2.5:7b`

프롬프트 입력 상한은 프로바이더별로 다릅니다 — Ollama 10,000자 / NVIDIA 40,000자
(`config.json` 의 `ai.*.max_prompt_chars`). NVIDIA 쪽이 128k 컨텍스트라 잘려나가는 증거가 적습니다.

#### 모델 선택 기준

출력이 전부 한국어 서술이고, MITRE 기법을 `T1055.012|Process Hollowing|Defense Evasion|근거`
파이프 형식으로 뽑아 **실제 리포트에 병합**하므로 — 한국어 품질 · 형식 준수 · 낮은 추측성 순으로 중요합니다.

| 모델 | 한국어 | 형식 준수 | 추측 억제 | 비고 |
|---|:---:|:---:|:---:|---|
| `qwen/qwen2.5-72b-instruct` | ◎ | ◎ | ○ | **기본값 · 권장** |
| `meta/llama-3.3-70b-instruct` | ○ | ◎ | ○ | 한국어가 다소 번역투 |
| `deepseek-ai/deepseek-r1` | ○ | △ | △ | 실행 흐름 추론 강함. 느리고 크레딧 소모 큼 |
| `nvidia/llama-3.1-nemotron-70b-instruct` | △ | ◎ | ○ | 영어 중심 |
| `*-coder-*` 계열 | △ | ○ | ○ | **부적합** — 코드 생성이 아닌 한국어 위협 서술 작업 |

reasoning 모델(`deepseek-r1` 등)은 `<think>` 블록이 자동 제거되고, 사고 과정이 `max_tokens` 를
소진해 빈 응답이 되는 것을 막기 위해 상한이 자동으로 16384 로 올라갑니다
(`config.json` 의 `ai.nvidia.max_tokens` 로 수동 지정 가능).

사용 가능한 모델 목록은 카탈로그에서 직접 확인하세요:

```bash
python -c "import os; from core.ai_analyzer import list_nvidia_models as L; print('\n'.join(L('https://integrate.api.nvidia.com/v1', os.environ['NVIDIA_API_KEY'])))"
```

### 관련도 등급 · 베이스라인 차감

분석 VM 은 샘플과 무관하게 배경 활동을 만듭니다. Windows Update 가 한 번 돌면
프로세스 80여 개 · 드롭 파일 170여 개 · HTTP 75건이 리포트에 들어와 정작 샘플이
남긴 아티팩트를 덮어버립니다. 이를 막기 위해 관측 항목마다 3단계 등급을 매깁니다.

| 등급 | 의미 | 리포트 기본 표시 |
|---|---|---|
| **1 계보** | 샘플 프로세스와 그 자손이 직접 발생시킨 행위 | 펼침 |
| **2 의심** | 계보 밖이지만 환경 배경으로 설명되지 않는 행위 — 주입·측면 이동 가능성 | 펼침 |
| **3 배경** | 베이스라인 또는 알려진 OS 배경 활동 (Windows Update·Defender·텔레메트리) | 숨김 |

> **데이터는 하나도 삭제되지 않습니다.** 등급은 HTML 리포트의 표시만 제어하고,
> 상단 `계보만 / 계보+의심 / 전체 표시` 버튼으로 언제든 되돌릴 수 있습니다.
> JSON 리포트에는 항상 전부 들어가며 각 항목에 `relevance_tier` 가 붙습니다.

판정 순서는 계보 확정 → 배경 제거 → **남는 것은 전부 의심** 입니다.
"모르면 배경" 이 아니라 "모르면 의심" 이어야 놓치지 않습니다.

#### 베이스라인 수집 (권장)

내장 OS 배경 프로파일만으로도 동작하지만, 해당 VM 에서 실제로 수집한
베이스라인이 훨씬 정확합니다. 샘플 없이 한 번 공회전시켜 저장합니다.

```powershell
# 1) 베이스라인 수집 — 샘플 없이 모니터링만 (Windows Update 가 도는 시간을 충분히 확보)
python analyzer.py --baseline-capture --timeout 600

# 2) 이후 분석은 baseline/<hostname>.json 을 자동 적용
python analyzer.py malware.exe

# 특정 베이스라인 지정 / 비활성화
python analyzer.py malware.exe --baseline baseline/vm01.json
python analyzer.py malware.exe --no-baseline
```

베이스라인은 호스트별로 저장됩니다(VM 마다 배경 활동이 다름). Defender 서명
버전과 업데이트 대상이 계속 바뀌므로 14일이 지나면 재수집 경고가 표시됩니다.

경로는 정규화 후 비교합니다 — `C:\Windows\TEMP\{GUID}\`, `appx.<랜덤>.tmp`,
버전 번호, 사용자 디렉터리명처럼 실행마다 달라지는 요소는 와일드카드로 치환되므로
원문이 매번 달라도 같은 배경 활동으로 인식됩니다.

### PCAP 분석

```powershell
# Wireshark에서 미리 캡처한 파일을 분석에 사용
python analyzer.py malware.exe --pcap capture.pcapng

# PCAP만 단독 분석 (샘플 실행 없이)
python analyzer.py --pcap capture.pcapng --no-procmon --no-tshark

# 전체 시스템 모니터링 모드 (샘플 미지정)
python analyzer.py --timeout 120
```

### 유틸리티

```powershell
# 도구 설치 상태 확인
python analyzer.py --check-tools

# tshark 인터페이스 목록 확인
python analyzer.py --list-interfaces
```

### config.json 설정

```json
{
  "capa": {
    "enabled": true,
    "path": "capa.exe",
    "timeout": 120
  },
  "virustotal": {
    "enabled": false,
    "api_key": "YOUR_VT_API_KEY",
    "timeout": 20
  }
}
```

---

## 분석 흐름

```
python analyzer.py malware.exe --memdump --ai
        │
        ▼
[1/6] 사전 스냅샷       레지스트리 + 프로세스 목록 저장
        │
        ▼
[2/6] 모니터링 시작     ProcMon 백그라운드 실행
                        tshark 패킷 캡처 시작 (또는 FakeNet-NG)
                        TLS 키 로거 활성화 (SSLKEYLOGFILE)
                        Process Hacker GUI 실행 (선택)
        │
        ▼
[3/6] 샘플 실행         malware.exe 자동 실행, PID 기록
        │
        ▼
[4/6] 대기              5초 간격 폴링, 샘플 조기 종료 감지
                        ProcessWatcher: 1초 폴링으로 신규 PID 즉시 pe-sieve 스캔
        │
        ▼
[5/6] 종료              ProcMon /Terminate → PML → CSV 변환
                        tshark 종료 → pcap 저장
                        TLS 세션 키 수집 완료
                        hollows_hunter 전체 시스템 스캔
                        pe-sieve 신규 프로세스 스캔 (잔존 PID 대상)
        │
        ▼
[6/6] 분석              사후 스냅샷 → 레지스트리·프로세스 diff
                        ProcMon CSV 파싱 + 노이즈 필터
                        PCAP 파싱 (연결, DNS, TLS SNI, HTTP, SMTP, FTP)
                        TLS 세션 키로 HTTPS 복호화 (decrypted_requests)
                        FakeNet-NG 결과 파싱 (DNS/HTTP/TCP 연결 시도)
                        프로세스↔네트워크 연결 매핑
                        MITRE ATT&CK 매핑
                        CAPA 정적 분석 → ATT&CK 기법 병합
                        쉘코드 덤프 재분석 (YARA + CAPA --shellcode)
                        VirusTotal 조회 → ATT&CK 기법 병합 (선택)
                        IOC 추출 (SMTP/FTP C2 IP 포함)
                        물리 메모리 덤프 (winpmem) ← --memdump
                        Volatility3 병렬 실행 (malfind·pstree·netscan·cmdline·handles·dlllist)
                        AI 행위 분석 (NVIDIA NIM → Ollama 폴백) ← 기본 ON, --no-ai 로 비활성화
        │
        ▼
      리포트             results/<이름>_<timestamp>/
                          ├── <name>_dynamic_report.html   ← 완료 후 자동 열기
                          ├── <name>_dynamic_report.json
                          ├── procmon.pml
                          ├── procmon.csv
                          ├── capture.pcap
                          ├── memory.raw                   ← --memdump
                          └── dumps/                       ← pe-sieve raw dump
                              └── process_<pid>/
                                  ├── *.exe / *.dll
                                  └── *.shc / *.bin
```

---

## HTML 리포트 탭 구성

| 탭 | 내용 |
|----|------|
| 🔍 **기본 분석** | 분석 요약 카드 (도구 상태·IOC 수·탐지 기법 수) |
| 🎯 **ATT&CK** | MITRE ATT&CK 기법 테이블 (전술·기법·증거·출처) |
| ⚙️ **프로세스** | 신규/종료 프로세스, pe-sieve 탐지 결과 |
| 📁 **파일** | ProcMon 파일 이벤트 (Write·Create·Rename·Delete) |
| 🗝️ **레지스트리** | ProcMon 레지스트리 이벤트 + Regshot diff |
| 🌐 **네트워크** | 외부 연결·DNS·TLS SNI·HTTP·SMTP/FTP·HTTPS 복호화·FakeNet-NG |
| 🧠 **메모리** | pe-sieve/HH 인젝션 탐지 + Volatility3 포렌식 (malfind·pstree·netscan·handles) |
| 🔎 **IOC** | 외부 IP·도메인·드롭 파일·레지스트리 키·URL (프로세스 매핑 포함) |
| 🤖 **AI 분석** | LLM 행위 분석 — 패밀리 추정·위협 수준·행위 요약·C2 패턴 (한국어), 사용된 프로바이더/모델 표기 |
| 🕵️ **Hunt** | abuse.ch 실시간 IOC 조회 (MalwareBazaar·ThreatFox·URLhaus·Feodo) |

---

## 프로젝트 구조

```
dynamic_analyzer/
├── analyzer.py               # CLI 진입점
├── requirements.txt
├── config.json               # CAPA·VT 설정
├── README.md
│
├── core/
│   ├── orchestrator.py       # 분석 워크플로우 총괄
│   ├── procmon.py            # ProcMon 제어 (시작/종료/CSV 변환)
│   ├── tshark_capture.py     # tshark 패킷 캡처
│   ├── registry_snapshot.py  # winreg 스냅샷 + diff
│   ├── process_tracker.py    # psutil 프로세스 추적 + 분석 도구 필터
│   ├── process_watcher.py    # 실시간 신규 PID 감지 + 즉시 pe-sieve 스캔
│   ├── pesieve_scanner.py    # pe-sieve 실행 래퍼
│   ├── hollows_hunter.py     # hollows-hunter 실행 래퍼
│   ├── tls_keylog.py         # SSLKEYLOGFILE 기반 TLS 세션 키 수집
│   ├── fakenet_integrator.py # FakeNet-NG 실행 + 결과 파싱
│   ├── memory_forensics.py   # winpmem 메모리 덤프 + Volatility3 포렌식
│   ├── ai_analyzer.py        # AI 행위 분석 (NVIDIA NIM / Ollama 공통)
│   ├── config_loader.py      # config.json 로더
│   ├── baseline.py           # 환경 노이즈 베이스라인 수집·저장·차감
│   └── vm_setup.py           # 캡처 최적화 레지스트리 정책 자동 적용
│
├── parsers/
│   ├── procmon_csv.py        # ProcMon CSV → ProcMonEvent 파싱
│   ├── pcap_parser.py        # PCAP → 연결/DNS/TLS SNI/HTTP/SMTP/FTP
│   └── pesieve_result.py     # pe-sieve / hollows-hunter JSON 파싱
│
├── analysis/
│   ├── noise_filter.py       # 시스템·분석 도구 노이즈 제거 (이벤트 단위)
│   ├── relevance.py          # 관련도 3단계 등급 (계보/의심/배경) 부여
│   ├── behavior_classifier.py # MITRE ATT&CK 매핑
│   ├── ioc_extractor.py      # IOC 추출 (SMTP/FTP C2 IP 포함)
│   ├── process_network_map.py # 프로세스↔네트워크 연결 매핑
│   ├── injection_classifier.py # 인젝션 유형 분류
│   ├── shellcode_analyzer.py # 쉘코드 덤프 재분석 (YARA + CAPA --shellcode)
│   ├── capa_analyzer.py      # CAPA 정적 분석 래퍼
│   ├── vt_analyzer.py        # VirusTotal API 연동
│   ├── yara_scanner.py       # YARA 룰 스캔
│   └── attack_lookup.py      # ATT&CK T-ID → 이름·전술 조회 테이블
│
├── exporters/
│   ├── html_report.py        # 다크 테마 HTML 리포트 (검색바 + 페이지네이션)
│   └── json_report.py        # 구조화 JSON 저장
│
└── rules/
    └── yaraify/              # YARA 룰 디렉터리 (YARAify 형식)
```

---

## 탐지 가능한 MITRE ATT&CK 기법

| ID | 기법 | 전술 |
|----|------|------|
| T1055.001 | Process Injection: DLL Injection | Defense Evasion |
| T1055.002 | Process Injection: PE Injection | Defense Evasion |
| T1055.012 | Process Hollowing | Defense Evasion |
| T1059.001 | PowerShell | Execution |
| T1059.003 | Windows Command Shell | Execution |
| T1059.005 | Visual Basic | Execution |
| T1218.010 | Regsvr32 | Defense Evasion |
| T1218.011 | Rundll32 | Defense Evasion |
| T1547.001 | Registry Run Keys | Persistence |
| T1547.004 | Winlogon Helper DLL | Persistence |
| T1543.003 | Windows Service | Persistence |
| T1546.010 | AppInit DLLs | Persistence |
| T1546.012 | Image File Execution Options | Persistence |
| T1027 | Obfuscated Files | Defense Evasion |
| T1070.004 | File Deletion | Defense Evasion |
| T1486 | Data Encrypted for Impact | Impact |
| T1490 | Inhibit System Recovery | Impact |
| T1071.001 | Web Protocols (HTTP/S) | Command and Control |
| T1071.002 | File Transfer Protocols (FTP) | Command and Control |
| T1071.003 | Mail Protocols (SMTP) | Command and Control |
| T1071.004 | DNS | Command and Control |
| T1095 | Non-Application Layer Protocol | Command and Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1114 | Email Collection (SMTP 탈취) | Collection |

> CAPA 및 VirusTotal 연동 시 추가 기법이 자동으로 병합됩니다.

---

## 변경 이력

### v1.8 — AI 분석 · 메모리 포렌식 · TLS 복호화 · FakeNet-NG

- **🤖 AI 행위 분석** (`core/ai_analyzer.py` 신규)
  - Ollama 로컬 LLM(기본: `qwen2.5:7b`) 기반 한국어 자동 위협 분석
  - 분석 항목 4개: 악성코드 패밀리 추정 · 위협 수준 평가 · 행위 분석 · C2 통신 패턴
  - 프롬프트 구성: MITRE ATT&CK 전술별 그룹 + 프로세스·파일·레지스트리·네트워크 행위 데이터
  - 10,000자 프롬프트 한도, `temperature=0.2` (사실 기반 일관성), `num_ctx=8192`
  - Ollama 미실행 또는 모델 미설치 시 자동 스킵, `--ai` 옵션으로 활성화

- **🧠 물리 메모리 덤프 + Volatility3** (`core/memory_forensics.py` 신규)
  - winpmem / DumpIt으로 RAM 전체 덤프 후 Volatility3 플러그인 병렬 실행
  - 실행 플러그인: `windows.malfind` · `windows.pstree` · `windows.netscan` · `windows.cmdline` · `windows.handles` · `windows.dlllist`
  - 플러그인 오류 원인 보고: 심볼 파일 없음 · 타임아웃 · JSON 파싱 오류 → HTML에 상세 표시
  - `--memdump`, `--winpmem-path`, `--vol-path`, `--dump-timeout`, `--dump` (기존 덤프 재사용) 옵션 지원

- **🔐 TLS 세션 키 복호화** (`core/tls_keylog.py` 신규)
  - `SSLKEYLOGFILE` 환경변수를 샘플 프로세스에 자동 주입 → HTTPS 평문 재구성
  - tshark로 TLS 세션 키 적용 후 HTTP2/HTTP1 요청 추출
  - 복호화된 요청은 네트워크 탭 "HTTPS 복호화" 섹션에 별도 표시
  - `--no-keylog` 옵션으로 비활성화

- **🌐 FakeNet-NG 연동** (`core/fakenet_integrator.py` 신규)
  - 가짜 DNS/HTTP/TCP 서버로 C2 응답 시뮬레이션 (tshark 대체 또는 병행)
  - 악성코드가 연결 시도하는 도메인·URL·TCP 세션 자동 수집
  - 결과는 네트워크 탭 "FakeNet-NG" 섹션에 표시
  - `--fakenet`, `--fakenet-path` 옵션 지원

- **HTML 리포트 탭 확장** (`exporters/html_report.py`)
  - **AI 분석 탭** 신규: 마크다운 → HTML 렌더링, 모델명·프롬프트 길이·소요시간 메타 표시
  - **네트워크 탭**: HTTPS 복호화 섹션 · FakeNet-NG DNS/HTTP/TCP 섹션 추가
  - **메모리 탭**: Volatility3 malfind · pstree · netscan · handles · cmdline 테이블 추가, 플러그인 오류 접기(`<details>`) 표시
  - `pcap=None`일 때 decrypted_requests / FakeNet 결과도 정상 렌더링 (조기 반환 버그 수정)
  - IOC 탭: 드롭 파일 프로세스 매핑 정확도 향상 (WriteFile + CreateFile/Created + RenameFile 처리)

---

### v1.7 — HTML 리포트 품질 개선 · 프로세스/메모리 탭 정확도 향상

- **프로세스 탭 정상 프로세스 필터링** (`exporters/html_report.py`)
  - `svchost.exe`, `explorer.exe`, `dwm.exe` 등 시스템 프로세스를 프로세스 트리·테이블에서 자동 제외
  - **악성코드 실행 체인 보존**: 악성 프로세스가 생성한 자식은 이름이 시스템 프로세스명이어도 표시

- **프로세스 탭 데이터 소스 명확화** (`core/orchestrator.py`)
  - pe-sieve 스캔 PID를 `new_processes`에 주입하던 "보완 블록" 완전 제거
  - 프로세스 트리/탭은 OS 스냅샷(psutil 전·후 diff)만 사용, pe-sieve 결과는 메모리 탭 전용

- **메모리 탭 시스템 프로세스 오탐 필터링** (`exporters/html_report.py`)
  - hollows-hunter / pe-sieve가 탐지한 결과 중 화이트리스트 프로세스 + PE인젝션·교체 없음 → 자동 숨김
  - 실제 PE인젝션(`implanted_pe > 0`) 또는 교체(`replaced > 0`) 탐지 시 화이트리스트여도 표시

- **MITRE ATT&CK 탭 연동 상태 표시** (`core/orchestrator.py`, `exporters/html_report.py`)
  - CAPA / VirusTotal 실행 결과를 상태 칩으로 표시

- **네트워크 탭 도메인 컬럼 추가** (`exporters/html_report.py`)
  - 연결 테이블에 "도메인" 독립 컬럼 추가 (DNS 응답 + TLS SNI 합산)

---

### v1.6 — 쉘코드 재분석 · CAPA/VT 통합 · 이벤트 필터 개선

- **쉘코드 덤프 재분석** (`analysis/shellcode_analyzer.py` 신규)
- **CAPA 정적 분석 통합** (`analysis/capa_analyzer.py` 신규)
- **VirusTotal ATT&CK 조회** (`analysis/vt_analyzer.py` 신규)
- **🧠 메모리 탭 개편** — 덤프 파일 MD5·SHA256 해시, YARA 룰명·CAPA ATT&CK 배지

### v1.5 — Hunt 탭 · 탭 분리 · VM 자동 세팅

- **Hunt 탭 추가** — abuse.ch 실시간 IOC 조회 (브라우저 직접 API 호출)
- **HTML 리포트 탭 구조 재편** — ATT&CK · 프로세스 · Hunt 탭 분리
- **VM 자동 세팅** (`core/vm_setup.py` 신규) — Chrome/Edge/Firefox DoH·QUIC·LLMNR·NetBIOS 비활성화

### v1.4 — pe-sieve 통합 · SMTP/FTP C2 분석 · HTML 검색바

- pe-sieve / hollows-hunter 통합, ProcessWatcher 1초 폴링
- SMTP/FTP C2 통신 분석 (`parsers/pcap_parser.py`)
- HTML 리포트 전 탭 검색바 + 페이지네이션

### v1.3 — 프로세스↔네트워크 매핑 · 노이즈 필터 강화

- `analysis/process_network_map.py` 신규 — ProcMon TCP/UDP 기반 프로세스별 연결 집계

### v1.2 — PCAP 분석 강화 · HTML 페이지네이션

- scapy 없이 PCAP 분석 (tshark fallback)
- 외부 PCAP 파일 지원 (`--pcap`), TLS SNI 분석

### v1.1 — 초기 기능 개선

- PCAP 분석, 비콘 탐지, DGA / 고엔트로피 도메인 탐지

---

## 주의사항

- **반드시 격리된 VM에서 실행**하세요 (FLARE VM, REMnux 등)
- 실제 악성코드를 호스트 PC에서 실행하지 마세요
- `results/` 디렉터리는 `.gitignore`에 포함되어 있습니다
- ProcMon은 서명된 드라이버가 필요하므로 Secure Boot가 활성화된 환경에서는 동작하지 않을 수 있습니다
- `--memdump`는 관리자 권한 + winpmem 드라이버 로드가 필요합니다

---

## 참고

- [Noriben](https://github.com/Rurik/Noriben) — ProcMon 기반 동적 분석 스크립트 (영감 출처)
- [FLARE VM](https://github.com/mandiant/flare-vm) — Windows 악성코드 분석 환경
- [Sysinternals ProcMon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CAPA](https://github.com/mandiant/capa) — 실행 파일 기능 탐지
- [pe-sieve](https://github.com/hasherezade/pe-sieve) — 프로세스 인젝션 탐지
- [hollows-hunter](https://github.com/hasherezade/hollows_hunter) — 전체 시스템 인젝션 스캔
- [Volatility3](https://github.com/volatilityfoundation/volatility3) — 메모리 포렌식 프레임워크
- [Ollama](https://ollama.com) — 로컬 LLM 실행 환경
- [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng) — 네트워크 시뮬레이션 도구
