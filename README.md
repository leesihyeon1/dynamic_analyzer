# dynamic_analyzer

Windows 악성코드 동적 분석 자동화 도구.  
ProcMon · tshark · pe-sieve · hollows-hunter · CAPA · YARA 를 조합해 **Noriben.py** 스타일로 동작하며,  
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
| **레지스트리 diff** | 실행 전·후 winreg 스냅샷 비교 (Regshot 대체) |
| **프로세스 추적** | psutil로 자식 PID 추적, 신규/종료 프로세스 감지 |
| **실시간 프로세스 감시** | 1초 폴링으로 신규 PID 즉시 pe-sieve 스캔 (타이밍 문제 해소) |
| **pe-sieve / hollows-hunter** | 프로세스 인젝션·PE 할로잉·쉘코드 삽입 탐지, raw dump 자동 추출 |
| **쉘코드 덤프 재분석** | pe-sieve/HH가 덤프한 `.shc`·`.bin` 파일에 YARA + CAPA `--shellcode` 적용, 오탐 필터링 포함 |
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
- **관리자 권한** (ProcMon, tshark 모두 필요)
- **FLARE VM** 또는 동적 분석 전용 VM 환경 권장

```powershell
pip install -r requirements.txt
```

```
psutil>=5.9.0
scapy>=2.5.0   # 없으면 tshark fallback 파서로 자동 대체
rich>=13.7.0
yara-python    # 선택 — 쉘코드 YARA 스캔 (pip install yara-python)
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

---

## 사용법

### 기본 실행

```powershell
# 관리자 PowerShell에서 실행
python analyzer.py malware.exe
```

### 옵션

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

# Process Hacker GUI 실행 안 함
python analyzer.py malware.exe --no-ph

# 파일 저장 없이 콘솔 출력만
python analyzer.py malware.exe --no-export

# 분석 완료 후 HTML 리포트 자동 열기 비활성화
python analyzer.py malware.exe --no-open
```

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
python analyzer.py malware.exe
        │
        ▼
[1/6] 사전 스냅샷       레지스트리 + 프로세스 목록 저장
        │
        ▼
[2/6] 모니터링 시작     ProcMon 백그라운드 실행
                        tshark 패킷 캡처 시작
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
                        Process Hacker / SystemInformer 종료
                        hollows_hunter 전체 시스템 스캔
                        pe-sieve 신규 프로세스 스캔 (잔존 PID 대상)
        │
        ▼
[6/6] 분석              사후 스냅샷 → 레지스트리·프로세스 diff
                        조기 종료 프로세스 pe-sieve 결과로 보완
                        ProcMon CSV 파싱 + 노이즈 필터
                        인젝션 대상 PID 이벤트 자동 포함
                        PCAP 파싱 (연결, DNS, TLS SNI, HTTP, SMTP, FTP)
                        프로세스↔네트워크 연결 매핑
                        MITRE ATT&CK 매핑
                        CAPA 정적 분석 → ATT&CK 기법 병합
                        쉘코드 덤프 재분석 (YARA + CAPA --shellcode)
                        VirusTotal 조회 → ATT&CK 기법 병합 (선택)
                        IOC 추출 (SMTP/FTP C2 IP 포함)
        │
        ▼
      리포트             results/<이름>_<timestamp>/
                          ├── <name>_dynamic_report.html   ← 완료 후 자동 열기
                          ├── <name>_dynamic_report.json
                          ├── procmon.pml
                          ├── procmon.csv
                          ├── capture.pcap
                          └── pe_dumps/                    ← pe-sieve raw dump
                              └── process_<pid>/
                                  ├── *.exe / *.dll        ← PE 덤프
                                  └── *.shc / *.bin        ← 쉘코드 덤프
```

---

## 출력 예시

### 콘솔

```
─────────────── 🧪 dynamic_analyzer — malware.exe ───────────────
  대상   : C:\samples\malware.exe
  출력   : results\malware_20260526_120000
  timeout: 60초

  [캡처 최적화] Chrome DoH  Chrome QUIC  Edge DoH  Edge QUIC  Firefox DoH  LLMNR  NetBIOS-NS
  [도구 확인] ProcMon=✔  tshark=✔  RegSnap=✔  ProcHacker=✔
  [1/6] 사전 스냅샷 수집 중...
  [2/6] 모니터링 시작...
  [3/6] 샘플 실행: malware.exe
        PID: 4832
  [4/6] 모니터링 중... (60초)
        5s 경과 / 잔여 55s...
        샘플 종료 감지 (15s)
  [5/6] 모니터링 종료...
        ProcMon 로그 변환 중...
        hollows-hunter 스캔: 의심 프로세스 3개
        Process Hacker 종료됨
  [6/6] 사후 스냅샷 수집 중...
        [보완] 조기 종료 프로세스 1개 추가 (malware.exe)
  [분석] ProcMon CSV 파싱...
        이벤트 18,432개 → 필터 후 512개
  [분석] CAPA 정적 분석 중...
        CAPA 완료: 기법 7개 탐지 (누적 7개)
  [분석] 쉘코드 덤프 재분석 중 (YARA + CAPA --shellcode)...
        쉘코드 파일 3개 분석  시그니처 히트 2개 🚨

  MITRE 기법       9건
  외부 IP          2개
  드롭 파일        1개
  레지스트리 추가  4건
  신규 프로세스    2개
  ProcMon 이벤트   18,432개 → 필터 후 512개

탐지된 MITRE ATT&CK 기법:
  ✔ T1055.001  Process Injection: DLL Injection  Defense Evasion
  ✔ T1059.003  Windows Command Shell  Execution
  ✔ T1547.001  Registry Run Keys / Startup Folder  Persistence

  [*] 결과 저장 중...
  JSON → results\malware_20260526_120000\malware_dynamic_report.json
  HTML → results\malware_20260526_120000\malware_dynamic_report.html
────────────────────── 분석 완료 ──────────────────────
```

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
│   ├── config_loader.py      # config.json 로더
│   └── vm_setup.py           # 캡처 최적화 레지스트리 정책 자동 적용
│
├── parsers/
│   ├── procmon_csv.py        # ProcMon CSV → ProcMonEvent 파싱
│   ├── pcap_parser.py        # PCAP → 연결/DNS/TLS SNI/HTTP/SMTP/FTP
│   └── pesieve_result.py     # pe-sieve / hollows-hunter JSON 파싱
│
├── analysis/
│   ├── noise_filter.py       # 시스템·분석 도구 노이즈 제거
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

### v1.6 — 쉘코드 재분석 · CAPA/VT 통합 · 이벤트 필터 개선

- **쉘코드 덤프 재분석** (`analysis/shellcode_analyzer.py` 신규)
  - pe-sieve / hollows-hunter 가 `process_<pid>/` 에 덤프한 `.shc`·`.bin` 파일을 자동 재분석
  - YARA 룰 스캔 (`rules/yaraify/`) + CAPA `--shellcode` 플래그로 ATT&CK 기법 추출
  - 오탐 필터링 2단계:
    - **화이트리스트**: dwm, explorer, chrome, svchost 등 시스템/브라우저 프로세스 제외
    - **의심도 점수**: PE인젝션(+40), 프로세스할로잉(+40), 훅(+20), 쉘코드단독(+10) — 임계값 30 미만 제외
  - 신규 생성 PID는 점수 무관 포함 (드로퍼 즉시 종료 대응)
  - 발견된 ATT&CK 기법은 `behavior_report` 에 자동 병합

- **CAPA 정적 분석 통합** (`analysis/capa_analyzer.py` 신규)
  - 샘플 바이너리에 CAPA 적용, 결과 ATT&CK 기법을 메모리·ATT&CK 탭에 통합 표시
  - `config.json` > `capa.enabled / path / timeout` 으로 제어

- **VirusTotal ATT&CK 조회** (`analysis/vt_analyzer.py` 신규)
  - SHA256 기반 `/files/{hash}/behaviours` + `behaviour_summary` 엔드포인트 조회
  - `config.json` > `virustotal.enabled / api_key / timeout` 으로 제어 (기본 비활성)

- **🧠 메모리 탭 개편** (`exporters/html_report.py`)
  - 쉘코드 덤프 재분석 결과 섹션 추가 (YARA 룰명 · CAPA ATT&CK 배지)
  - 덤프 파일별 **MD5·SHA256** 해시 표시
  - 전체 경로 접힘(`<details>`) + 파일명·크기 헤더

- **이벤트 필터 개선** (`core/orchestrator.py`)
  - HH/pe-sieve가 탐지한 인젝션 대상 프로세스 PID를 `focus_pids` 에 자동 포함  
    → 드로퍼가 dwm.exe·PanGPA.exe 등 기존 프로세스에 주입한 경우에도 파일·레지스트리 이벤트 표시
  - 조기 종료된 샘플(드로퍼·로더)을 pe-sieve 스캔 결과로 프로세스 탭에 보완  
    → proc_after 스냅샷 이전에 종료된 프로세스도 프로세스 탭에 표시

- **pe-sieve / hollows-hunter 파싱 개선** (`parsers/pesieve_result.py`, `core/hollows_hunter.py`, `core/pesieve_scanner.py`)
  - HH summary.json 형식 양방향 파싱 (full output / summary 자동 감지)
  - 다중 JSON 키 후보 처리 (버전별 차이 흡수)
  - 덤프 디렉터리 경로 자동 해석

### v1.5 — Hunt 탭 · 탭 분리 · VM 자동 세팅

- **Hunt 탭 추가** (`exporters/html_report.py`)
  - HTML 리포트 내 `🕵️ Hunt` 탭 신규 추가
  - 검색 입력창에 해시(MD5/SHA1/SHA256) · IP · URL · 도메인을 입력하면 **브라우저에서 직접 abuse.ch API 조회** (서버 불필요, CORS 허용)
  - 지원 서비스:
    - **MalwareBazaar** — 해시(MD5/SHA1/SHA256) 악성코드 데이터베이스
    - **ThreatFox** — 해시/IP/URL/도메인 IOC 조회
    - **URLhaus** — IP/URL/도메인 악성 URL 조회
    - **Feodo Tracker** — IP 봇넷 C2 서버 조회
  - IOC 타입 자동 감지(정규식) → 적합한 서비스만 활성화
  - 현재 분석 결과에서 추출된 IOC(외부IP·도메인·드롭파일 SHA256)를 **Quick 버튼**으로 원클릭 검색
  - 각 서비스별 상태 배지(대기/조회중/탐지됨/클린/오류) 실시간 업데이트

- **HTML 리포트 탭 구조 재편** (`exporters/html_report.py`)
  - `🔍 기본 분석` 탭: 개요 카드만 표시 (요약 중심)
  - `🎯 ATT&CK` 탭 분리: MITRE ATT&CK 기법 테이블 독립 탭으로 이동
  - `⚙️ 프로세스` 탭 분리: 신규 프로세스·pe-sieve 탐지 테이블 독립 탭으로 이동
  - `🕵️ Hunt` 탭 신규 추가 (우측 끝)

- **VM 자동 세팅** (`core/vm_setup.py` 신규, `analyzer.py`)
  - 스냅샷 복원 후 매 실행 시 `apply_capture_policies()` 자동 호출
  - 적용 항목 7가지 (관리자 권한 필요):
    | 정책 | 효과 |
    |------|------|
    | Chrome DoH 비활성화 | A 쿼리 평문 UDP 53으로 노출 |
    | Chrome QUIC 비활성화 | HTTP/3 → TLS(TCP) 강제, SNI 캡처 가능 |
    | Edge DoH 비활성화 | 동일 |
    | Edge QUIC 비활성화 | 동일 |
    | Firefox DoH 비활성화 | 동일 |
    | LLMNR 비활성화 | `.in-addr.arpa` PTR 노이즈 제거 |
    | NetBIOS-NS 비활성화 | UDP 137 브로드캐스트 노이즈 제거 |
  - 이미 적용된 경우 멱등(덮어쓰기) — 중복 실행 안전

### v1.4 — pe-sieve 통합 · SMTP/FTP C2 분석 · HTML 검색바

- **pe-sieve / hollows-hunter 통합**
  - 모니터링 중 `ProcessWatcher`: 1초 폴링으로 신규 PID를 즉시 pe-sieve 스캔
  - hollows_hunter 전체 시스템 스캔 (`/dmode 3`) + pe-sieve 신규 프로세스 개별 스캔 병행

- **SMTP/FTP C2 통신 분석** (`parsers/pcap_parser.py`)
  - AgentTesla, FormBook 등 정보탈취 악성코드의 SMTP(25/465/587/2525) · FTP(21/2121) 세션 자동 파싱

- **HTML 리포트 전 탭 검색바 + 페이지네이션 개선**

### v1.3 — 프로세스↔네트워크 매핑 · 노이즈 필터 강화

- `analysis/process_network_map.py` 신규: ProcMon TCP/UDP 기반 프로세스별 연결 집계
- 노이즈 필터 강화: ProcMon, tshark, SystemInformer, Process Hacker 이벤트 전체 제거

### v1.2 — PCAP 분석 강화 · HTML 페이지네이션

- scapy 없이 PCAP 분석 (tshark fallback)
- 외부 PCAP 파일 지원 (`--pcap`)
- HTML 페이지네이션, TLS SNI 분석

### v1.1 — 초기 기능 개선

- PCAP 분석, 비콘 탐지, DGA / 고엔트로피 도메인 탐지

---

## 주의사항

- **반드시 격리된 VM에서 실행**하세요 (FLARE VM, REMnux 등)
- 실제 악성코드를 호스트 PC에서 실행하지 마세요
- `results/` 디렉터리는 `.gitignore`에 포함되어 있습니다
- ProcMon은 서명된 드라이버가 필요하므로 Secure Boot가 활성화된 환경에서는 동작하지 않을 수 있습니다

---

## 참고

- [Noriben](https://github.com/Rurik/Noriben) — ProcMon 기반 동적 분석 스크립트 (영감 출처)
- [FLARE VM](https://github.com/mandiant/flare-vm) — Windows 악성코드 분석 환경
- [Sysinternals ProcMon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CAPA](https://github.com/mandiant/capa) — 실행 파일 기능 탐지
- [pe-sieve](https://github.com/hasherezade/pe-sieve) — 프로세스 인젝션 탐지
- [hollows-hunter](https://github.com/hasherezade/hollows_hunter) — 전체 시스템 인젝션 스캔
