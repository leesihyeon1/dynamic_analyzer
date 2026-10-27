"""관리자 권한에서 고정된 분석 진입점만 실행하고 로그를 파일에 기록한다."""
import os
from pathlib import Path
import runpy
import sys
import traceback


def main():
    log_path = Path(sys.argv[1])
    args = sys.argv[2:]
    os.environ["PYTHONIOENCODING"] = "utf-8"
    os.environ["NO_COLOR"] = "1"
    with log_path.open("a", encoding="utf-8", buffering=1) as log:
        sys.stdout = sys.stderr = log
        sys.argv = [str(Path(__file__).with_name("analyzer.py")), *args]
        try:
            runpy.run_path(sys.argv[0], run_name="__main__")
        except SystemExit:
            raise
        except BaseException:
            traceback.print_exc()
            raise SystemExit(1)
        finally:
            log.flush()
            sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

if __name__ == "__main__":
    main()
