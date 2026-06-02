# dynamic_analyzer

Windows 악성코드 동적 분석 자동화 도구.  
ProcMon · tshark · winreg · psutil 을 조합해 **Noriben.py** 스타일로 동작하며,  
실행 한 줄로 샘플 모니터링 → MITRE ATT&CK 매핑 → HTML/JSON 리포트까지 자동 생성합니다.

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **ProcMon 자동화** | 백그라운드 실행 → CSV 변환 → 파싱 |
| **패킷 캡처** | tshark로 pcap 수집, scapy/tshark로 연결/DNS/TLS SNI/HTTP 분석 |
| **외부 PCAP 분석** | `--pcap` 옵션으로 Wireshark 캡처 파일 직접 분석 |
| **scapy 없이 PCAP 분석** | scapy 미설치 시 tshark fallback 파서로 자동 대체 |
| **레지스트리 diff** | 실행 전·후 winreg 스냅샷 비교 (Regshot 대체) |
| **프로세스 추적** | psutil로 자식 PID 추적, 신규/종료 프로세스 감지 |
| **프로세스↔네트워크 매핑** | ProcMon TCP/UDP 이벤트 기반, 프로세스별 외부 연결 집계 |
| **노이즈 필터** | 시스템 프로세스 + 분석 도구(ProcMon·tshark·SystemInformer 등) 이벤트 자동 제거 |
| **MITRE ATT&CK** | 행동 패턴 → 기법 자동 매핑 (T1059, T1547, T1486 등) |
| **IOC 추출** | 외부 IP·도메인·드롭 파일·레지스트리 키·URL |
| **리포트 생성** | 다크 테마 HTML(페이지네이션 지원) + 구조화된 JSON |

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
```

### 선택 (자동 감지)
| 도구 | 기본 경로 | 없으면 |
|------|-----------|--------|
| **ProcMon** (`Procmon64.exe`) | `C:\Tools\SysinternalsSuite\` 또는 PATH | ProcMon 기능 스킵 |
| **tshark** (Wireshark 포함) | `C:\Program Files\Wireshark\` 또는 PATH | 패킷 캡처 스킵 |
| **Process Hacker** / **System Informer** | `C:\Tools\processhacker\` | psutil로 대체 |

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
        │
        ▼
[5/6] 종료              ProcMon /Terminate → PML → CSV 변환
                        tshark 종료 → pcap 저장
                        Process Hacker / SystemInformer 종료
        │
        ▼
[6/6] 분석              사후 스냅샷 → 레지스트리·프로세스 diff
                        ProcMon CSV 파싱 + 노이즈 필터
                        PCAP 파싱 (연결, DNS, TLS SNI, HTTP)
                        프로세스↔네트워크 연결 매핑
                        MITRE ATT&CK 매핑
                        IOC 추출
        │
        ▼
      리포트             results/<이름>_<timestamp>/
                          ├── <name>_dynamic_report.html
                          ├── <name>_dynamic_report.json
                          ├── procmon.pml
                          ├── procmon.csv
                          └── capture.pcap
```

---

## 출력 예시

### 콘솔

```
─────────────── 🧪 dynamic_analyzer — malware.exe ───────────────
  대상   : C:\samples\malware.exe
  출력   : results\malware_20260526_120000
  timeout: 60초

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
        Process Hacker 종료됨
  [6/6] 사후 스냅샷 수집 중...
  [분석] ProcMon CSV 파싱...
        이벤트 18,432개 → 필터 후 247개
  [분석] PCAP 파싱...
        연결 3개  DNS 5건
  [분석] 프로세스↔네트워크 연결 매핑...
        12개 연결 집계

  MITRE 기법       3건
  외부 IP          2개
  드롭 파일        1개
  레지스트리 추가  4건
  신규 프로세스    2개
  ProcMon 이벤트   18,432개 → 필터 후 247개

탐지된 MITRE ATT&CK 기법:
  ✔ T1059.003  Windows Command Shell  Execution
  ✔ T1547.001  Registry Run Keys / Startup Folder  Persistence
  ✔ T1071.001  Application Layer Protocol: Web Protocols  Command and Control

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
├── README.md
│
├── core/
│   ├── orchestrator.py       # 분석 워크플로우 총괄
│   ├── procmon.py            # ProcMon 제어 (시작/종료/CSV 변환)
│   ├── tshark_capture.py     # tshark 패킷 캡처
│   ├── registry_snapshot.py  # winreg 스냅샷 + diff
│   └── process_tracker.py    # psutil 프로세스 추적 + 분석 도구 필터
│
├── parsers/
│   ├── procmon_csv.py        # ProcMon CSV → ProcMonEvent 파싱
│   └── pcap_parser.py        # PCAP → 연결/DNS/TLS SNI/HTTP (scapy 또는 tshark fallback)
│
├── analysis/
│   ├── noise_filter.py       # 시스템·분석 도구 노이즈 제거
│   ├── behavior_classifier.py # MITRE ATT&CK 매핑
│   ├── ioc_extractor.py      # IOC 추출
│   └── process_network_map.py # 프로세스↔네트워크 연결 매핑 (신규)
│
└── exporters/
    ├── html_report.py        # 다크 테마 HTML 리포트 (페이지네이션)
    └── json_report.py        # 구조화 JSON 저장
```

---

## 탐지 가능한 MITRE ATT&CK 기법

| ID | 기법 | 전술 |
|----|------|------|
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
| T1071.004 | DNS | Command and Control |
| T1095 | Non-Application Layer Protocol | Command and Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |

---

## 변경 이력

### v1.3 — 프로세스↔네트워크 매핑 · 노이즈 필터 강화

- **프로세스↔네트워크 연결 매핑** (`analysis/process_network_map.py` 신규)
  - ProcMon TCP/UDP 이벤트 기반으로 프로세스별 외부 연결 자동 집계
  - HTML 리포트에 전용 섹션 추가, JSON 리포트에도 포함
- **분석 도구 노이즈 필터 강화**
  - `noise_filter.py`: ProcMon, tshark, SystemInformer, Process Hacker, ZoomIt 등 분석 도구 프로세스 이벤트 전체 제거
  - `process_tracker.py`: 신규 프로세스 목록에서 분석 도구 자동 제외
  - `ioc_extractor.py`: dropped_files IOC에서 분석 도구 경로 패턴 제외, `WriteFile`만 실제 드롭으로 판정 (`CreateFile` 제외)
- **분석 종료 후 자동 정리**: Process Hacker / System Informer 프로세스 자동 종료

### v1.2 — PCAP 분석 강화 · HTML 페이지네이션

- **scapy 없이 PCAP 분석**: scapy 미설치 시 tshark fallback 파서 자동 전환
- **외부 PCAP 파일 지원**: `--pcap <FILE>` 옵션으로 Wireshark 캡처 파일 직접 분석
- **HTML 페이지네이션**: 모든 결과 테이블에 1·2·3… 페이지 네비게이션 추가 (100행/페이지)
- **TLS SNI 분석**: HTTPS 트래픽의 도메인 식별 지원

### v1.1 — 초기 기능 개선

- PCAP 분석 (연결, DNS, HTTP)
- 비콘 탐지 (규칙적 C2 통신 감지)
- DGA / 고엔트로피 도메인 탐지

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
