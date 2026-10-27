"""기존 HTML의 분석 내용은 보존하고 새 레이아웃을 별도 파일로 저장한다."""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path, PureWindowsPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from exporters.html_report import _CSS, _JS
from exporters.report_theme import report_header


def restyle_report(source: Path, output: Path) -> None:
    if source.resolve() == output.resolve():
        raise ValueError("원본을 보존할 수 있도록 다른 출력 파일을 지정하세요.")
    data = json.loads(source.with_suffix(".json").read_text(encoding="utf-8-sig"))
    html = source.read_text(encoding="utf-8-sig")
    tools = re.search(r'<p style="margin-bottom:1.5rem">(.*?)</p>', html, re.S)
    if not tools:
        raise ValueError("지원되는 기존 보고서 헤더를 찾을 수 없습니다.")
    header = report_header(
        sample_name=PureWindowsPath(data.get("sample") or "분석 결과").name,
        sample_path=data.get("sample", ""), generated=datetime.fromtimestamp(source.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
        timeout=data.get("timeout", 0), duration=data.get("duration", 0),
        techniques=len(data.get("mitre_techniques", [])), events=data.get("events_summary", {}).get("total", 0),
        connections=len(data.get("network", {}).get("connections", [])), ips=len(data.get("iocs", {}).get("ip_addresses", [])),
        tools_html=tools[1], needs_review=bool(data.get("errors")) or bool(data.get("tools_used", {}).get("procmon") and not data.get("events_summary", {}).get("total")),
        indicator="기존 상세 결과 참고",
    )
    html, replaced = re.subn(r'<h1>.*?</h1>.*?<p style="margin-bottom:1.5rem">.*?</p>', lambda _: header, html, count=1, flags=re.S)
    if replaced != 1:
        raise ValueError("보고서 헤더를 변경하지 못했습니다.")
    html = re.sub(r'<style>.*?</style>', lambda _: "<style>" + _CSS + "</style>", html, count=1, flags=re.S)
    html = re.sub(r'<script>\s*function togglePT.*?</script>', lambda _: "<script>" + _JS + "</script>", html, count=1, flags=re.S)
    labels = {"basic": "분석 개요", "attack": "ATT&amp;CK 근거", "process": "프로세스", "filesystem": "파일 활동",
              "registry": "레지스트리", "network": "네트워크", "memory": "메모리", "ioc": "관찰 지표 · IOC", "hunt": "위협 조회 · Hunt", "ai": "AI 분석"}
    for name, label in labels.items():
        html = re.sub(r'(<button[^>]*data-tab="tab-' + name + r'"[^>]*>)\s*[^<]*', lambda m: m[1] + label, html, count=1)
    html = html.replace('<div class="tabs">', '<div class="tabs" role="navigation" aria-label="보고서 섹션">', 1)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    restyle_report(args.source, args.output)
    print(f"보고서 저장: {args.output}")
