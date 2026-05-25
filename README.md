# dynamic_analyzer

Windows 악성코드 동적 분석 자동화 도구.  
ProcMon · tshark · winreg · psutil 을 조합해 **Noriben.py** 스타일로 동작하며,  
실행 한 줄로 샘플 모니터링 → MITRE ATT&CK 매핑 → HTML/JSON 리포트까지 자동 생성합니다.

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **ProcMon 자동화** | 백그라운드 실행 → CSV 변환 → 파싱 |
| **패킷 캡처** | tshark로 pcap 수집, scapy로 연결/DNS/HTTP 분석 |
| **레지스트리 diff** | 실행 전·후 winreg 스냅샷 비교 (Regshot 대체) |
| **프로세스 추적** | psutil로 자식 PID 추적, 신규/종료 프로세스 감지 |
| **노이즈 필터** | 시스템 프로세스·경로 제거, 샘플 관련 이벤트만 집중 |
| **MITRE ATT&CK** | 행동 패턴 → 기법 자동 매핑 (T1059, T1547, T1486 등) |
| **IOC 추출** | 외부 IP·도메인·드롭 파일·레지스트리 키·URL |
| **리포트 생성** | 다크 테마 HTML + 구조화된 JSON |

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
scapy>=2.5.0
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
        │
        ▼
[6/6] 분석              사후 스냅샷 → 레지스트리·프로세스 diff
                        ProcMon CSV 파싱 + 노이즈 필터
                        PCAP 파싱 (연결, DNS, HTTP)
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
  [6/6] 사후 스냅샷 수집 중...
  [분석] ProcMon CSV 파싱...
        이벤트 18,432개 → 필터 후 247개
  [분석] PCAP 파싱...
        연결 3개  DNS 5건

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
│   └── process_tracker.py    # psutil 프로세스 추적
│
├── parsers/
│   ├── procmon_csv.py        # ProcMon CSV → ProcMonEvent 파싱
│   └── pcap_parser.py        # PCAP → 연결/DNS/HTTP (scapy)
│
├── analysis/
│   ├── noise_filter.py       # 시스템 노이즈 제거
│   ├── behavior_classifier.py # MITRE ATT&CK 매핑
│   └── ioc_extractor.py      # IOC 추출
│
└── exporters/
    ├── html_report.py        # 다크 테마 HTML 리포트
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
