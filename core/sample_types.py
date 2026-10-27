"""GUI와 실행기가 공유하는 문서·스크립트 지원 형식."""
SHELL_EXEC_SUFFIXES: frozenset[str] = frozenset({
    # Office 문서
    ".doc", ".docx", ".docm", ".dot", ".dotm",
    ".xls", ".xlsx", ".xlsm", ".xlt", ".xltm",
    ".ppt", ".pptx", ".pptm", ".pot", ".potm",
    ".rtf", ".pdf", ".odt", ".ods", ".odp",
    # 스크립트 / 웹 기반 실행 파일
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
    ".hta", ".ps1", ".psm1", ".psd1",
    # 링크 / URL
    ".url", ".lnk",
})

SAMPLE_SUFFIXES = SHELL_EXEC_SUFFIXES | {".exe"}
