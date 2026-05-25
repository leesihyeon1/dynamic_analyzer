"""
registry_snapshot.py - Windows registry snapshot and diff for dynamic malware analysis.

Takes before/after snapshots of persistence-relevant registry keys using the
built-in winreg module and computes the delta (added, modified, deleted values).

Only available on Windows.  AVAILABLE is set to False on other platforms so
callers can guard accordingly.
"""

from __future__ import annotations

try:
    import winreg
    AVAILABLE = True
except ImportError:
    winreg = None  # type: ignore[assignment]
    AVAILABLE = False


# ---------------------------------------------------------------------------
# Keys to monitor
# Each entry is (hive_constant, hive_name_for_display, subkey_path).
# ---------------------------------------------------------------------------
if AVAILABLE:
    WATCHED_KEYS: list[tuple[int, str, str]] = [
        # HKLM persistence locations
        (
            winreg.HKEY_LOCAL_MACHINE,
            "HKLM",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            "HKLM",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            "HKLM",
            r"SYSTEM\CurrentControlSet\Services",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            "HKLM",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            "HKLM",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",  # AppInit_DLLs lives here
        ),
        # WOW6432Node Run (32-bit apps on 64-bit Windows)
        (
            winreg.HKEY_LOCAL_MACHINE,
            "HKLM",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ),
        # HKCU persistence locations
        (
            winreg.HKEY_CURRENT_USER,
            "HKCU",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            winreg.HKEY_CURRENT_USER,
            "HKCU",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
    ]
else:
    WATCHED_KEYS = []


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def snapshot_key(hive: int, subkey_str: str) -> dict[str, object]:
    """Read all values under a single registry key.

    Parameters
    ----------
    hive:
        A winreg hive constant such as ``winreg.HKEY_LOCAL_MACHINE``.
    subkey_str:
        Path beneath the hive, e.g. ``r"SOFTWARE\\Microsoft\\...\\Run"``.

    Returns
    -------
    dict[str, object]
        Mapping of value name → value data.  Returns an empty dict if the key
        does not exist, cannot be opened, or winreg is unavailable.
    """
    if not AVAILABLE:
        return {}
    values: dict[str, object] = {}
    try:
        with winreg.OpenKey(hive, subkey_str, 0, winreg.KEY_READ) as key:
            index = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, index)
                    values[name] = data
                    index += 1
                except OSError:
                    # No more values
                    break
    except Exception:
        pass
    return values


def take_snapshot() -> dict[str, dict[str, object]]:
    """Capture the current state of all watched registry keys.

    Returns
    -------
    dict[str, dict[str, object]]
        Mapping of ``"HIVE\\\\subkey"`` → ``{value_name: value_data, ...}``.
        Keys that cannot be read are included with an empty dict.
    """
    snapshot: dict[str, dict[str, object]] = {}
    for hive_const, hive_name, subkey in WATCHED_KEYS:
        key_path = f"{hive_name}\\{subkey}"
        snapshot[key_path] = snapshot_key(hive_const, subkey)
    return snapshot


def diff_snapshots(
    before: dict[str, dict[str, object]],
    after: dict[str, dict[str, object]],
) -> dict[str, list]:
    """Compute the delta between two registry snapshots.

    Parameters
    ----------
    before:
        Snapshot taken before the analysis period (from ``take_snapshot()``).
    after:
        Snapshot taken after the analysis period (from ``take_snapshot()``).

    Returns
    -------
    dict with three keys:

    ``"added"``
        ``[(key_path, value_name, value_data), ...]`` – values present in
        *after* but not in *before*.

    ``"modified"``
        ``[(key_path, value_name, old_data, new_data), ...]`` – values whose
        data changed between snapshots.

    ``"deleted"``
        ``[(key_path, value_name, value_data), ...]`` – values present in
        *before* but absent in *after*.
    """
    added: list[tuple[str, str, object]] = []
    modified: list[tuple[str, str, object, object]] = []
    deleted: list[tuple[str, str, object]] = []

    # Collect all key paths from both snapshots
    all_key_paths = set(before.keys()) | set(after.keys())

    for key_path in all_key_paths:
        before_values = before.get(key_path, {})
        after_values = after.get(key_path, {})

        all_names = set(before_values.keys()) | set(after_values.keys())
        for name in all_names:
            in_before = name in before_values
            in_after = name in after_values

            if in_after and not in_before:
                added.append((key_path, name, after_values[name]))
            elif in_before and not in_after:
                deleted.append((key_path, name, before_values[name]))
            elif in_before and in_after and before_values[name] != after_values[name]:
                modified.append((key_path, name, before_values[name], after_values[name]))

    return {
        "added": added,
        "modified": modified,
        "deleted": deleted,
    }
