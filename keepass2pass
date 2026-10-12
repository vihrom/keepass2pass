#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Stefan Simroth <stefan.simroth@gmail.com>. All Rights Reserved.
# Based on the script for KeepassX by Juhamatti Niemelä <iiska@iki.fi>.
# This file is licensed under the GPLv2+. Please see LICENSE for more information.
#
# Contributor: Vitaliy Khatuntsev <vitalik.khatuntsev@gmail.com>
# Description: Ported to Python 3, refactored duplicate handling, interactive
#              CLI, safer imports (no silent overwrites, Recycle Bin skipped,
#              custom fields/OTP kept, strict path sanitizing, exit codes).
#
# Usage:
#   ./keepass2pass.py -f export.xml                  (keep KeePass root group name)
#   ./keepass2pass.py -f export.xml -r "CustomRoot"  (replace root group name)
#   ./keepass2pass.py -f export.xml -r ""            (flat: no root folder at all)
#   ./keepass2pass.py -f export.xml --dry-run        (show what would happen)
#
# Exit status: 0 success, 1 errors or failed inserts, 2 bad arguments.

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path
from subprocess import PIPE, CalledProcessError, run
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree

SEPARATOR = "---------"
PLACEHOLDER = "untitled"
HANDLED_KEYS = ("Title", "Password", "UserName", "URL", "Notes")
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f/]")
CHOICES = {"m": "merge", "s": "split", "ma": "merge", "sa": "split"}


def info(message: str) -> None:
    print(f"[INFO] {message}")


def warn(message: str) -> None:
    print(f"[WARN] {message}", file=sys.stderr)


def error(message: str) -> None:
    print(f"[ERROR] {message}", file=sys.stderr)


def sanitize_component(name: str) -> str:
    """Make one path component safe for pass: no '/', no control characters,
    never '.' or '..', never empty."""
    name = CONTROL_CHARS.sub("_", name).strip()
    if name in {".", ".."}:
        name = "_"
    return name or PLACEHOLDER


def join_path(parent: str, child: str) -> str:
    return f"{parent}/{child}" if parent else child


def normalize_root(root: str) -> str:
    """'a//b/' -> 'a/b'; '' stays '' (flat structure)."""
    return "/".join(sanitize_component(part) for part in root.split("/") if part.strip())


def entry_fields(entry: ElementTree.Element) -> Dict[str, str]:
    """All <String> key/value pairs of an entry (first occurrence wins)."""
    fields: Dict[str, str] = {}
    for node in entry.findall("String"):
        key = node.findtext("Key")
        if key and key not in fields:
            fields[key] = node.findtext("Value") or ""
    return fields


def format_entry(entry: ElementTree.Element, fields: Dict[str, str], label: str) -> str:
    """Render an entry in pass format. The first line is ALWAYS the password
    (empty if there is none), so that `pass -c` never copies a metadata line.
    Returns "" for entries with no content at all."""
    password = fields.get("Password", "")
    lines = [password]
    for key in ("UserName", "URL"):
        if fields.get(key):
            lines.append(f"{key}: {fields[key]}")
    for key, value in fields.items():
        if key in HANDLED_KEYS or not value:
            continue
        # pass-otp looks for a bare otpauth:// line, so no "key: " prefix
        lines.append(value if value.startswith("otpauth://") else f"{key}: {value}")
    tags = entry.findtext("Tags")
    if tags:
        lines.append(f"Tags: {tags}")
    if fields.get("Notes"):
        lines.append(f"Notes: {fields['Notes']}")

    if not any(lines):
        return ""
    if not password:
        warn(f"no password: {label}")

    for attachment in entry.findall("Binary"):
        warn(f"attachment {attachment.findtext('Key')!r} is not imported: {label}")
    if any("{REF:" in value for value in fields.values()):
        warn(f"contains a KeePass field reference ({{REF:...}}), copied literally: {label}")

    return "\n".join(lines) + "\n"


class Collector:
    """Walks the KeePass tree and collects `pass path -> entry text`."""

    def __init__(self, duplicates: str, bin_uuid: Optional[str]) -> None:
        self.entries: Dict[str, str] = {}
        self.duplicates = duplicates  # "ask", "merge" or "split"
        self.bin_uuid = bin_uuid

    def add_group(self, group: ElementTree.Element, path: str) -> None:
        """`path` is the final pass path of THIS group ("" = top level)."""
        for sub in group.findall("Group"):
            if self.bin_uuid and sub.findtext("UUID") == self.bin_uuid:
                info(f"skipping Recycle Bin: {join_path(path, sanitize_component(sub.findtext('Name') or ''))}")
                continue
            name = sanitize_component(sub.findtext("Name") or "")
            self.add_group(sub, join_path(path, name))
        for entry in group.findall("Entry"):
            self.add_entry(entry, path)

    def add_entry(self, entry: ElementTree.Element, group_path: str) -> None:
        fields = entry_fields(entry)
        path = join_path(group_path, sanitize_component(fields.get("Title", "")))
        data = format_entry(entry, fields, path)
        if not data:
            warn(f"empty entry skipped: {path}")
            return

        if path not in self.entries:
            self.entries[path] = data
        elif self.resolve_duplicate(path) == "merge":
            info(f"merging duplicate into: {path}")
            self.entries[path] += f"{SEPARATOR}\nPassword: {data}"
        else:
            counter = 2
            while f"{path}_{counter}" in self.entries:
                counter += 1
            info(f"splitting duplicate into: {path}_{counter}")
            self.entries[f"{path}_{counter}"] = data

    def resolve_duplicate(self, path: str) -> str:
        """Returns "merge" or "split"; may switch to a sticky strategy."""
        if self.duplicates != "ask":
            return self.duplicates

        print(f"\n[!] Duplicate path detected: {path}")
        while True:
            try:
                choice = input("    [m]erge, [s]plit, merge [ma]ll, split [sa]ll? ").strip().lower()
            except EOFError:
                error("cannot ask about duplicates without a terminal; use --duplicates merge|split")
                sys.exit(1)
            except KeyboardInterrupt:
                print()
                error("cancelled by user, nothing was imported")
                sys.exit(1)
            if choice in CHOICES:
                break
            print("    Invalid option. Please enter 'm', 's', 'ma' or 'sa'.")

        if len(choice) == 2:
            self.duplicates = CHOICES[choice]
        return CHOICES[choice]


def load_entries(xml_file: str, root_path: Optional[str], duplicates: str,
                 include_bin: bool) -> Optional[Dict[str, str]]:
    """Parse the KeePass2 XML export; returns None on a fatal error."""
    print(f"[>>>>] Reading XML file: {xml_file}")
    try:
        tree = ElementTree.parse(xml_file)
    except (ElementTree.ParseError, OSError) as err:
        error(f"cannot read {xml_file}: {err}")
        return None

    root = tree.getroot()
    root_group = root.find("Root/Group")
    if root_group is None:
        error("<Root>/<Group> not found: not a KeePass2 XML export?")
        return None

    if root_path is None:
        start = sanitize_component(root_group.findtext("Name") or "")
    else:
        start = normalize_root(root_path)
        info(f"root path: {start!r}" + (" (flat)" if not start else ""))

    bin_uuid = None if include_bin else (root.findtext("Meta/RecycleBinUUID") or None)
    collector = Collector(duplicates, bin_uuid)
    collector.add_group(root_group, start)
    return collector.entries


def store_dir() -> Path:
    return Path(os.environ.get("PASSWORD_STORE_DIR") or "~/.password-store").expanduser()


def pass_insert(path: str, data: str) -> Optional[str]:
    """Insert one entry via stdin. Returns None on success, else the reason.
    '--' keeps a path like '-foo' from being parsed as an option; --force is
    safe because existence is checked by the caller (pass would otherwise ask
    for confirmation on stdin, which carries the secret)."""
    try:
        run(["pass", "insert", "--multiline", "--force", "--", path],
            input=data, text=True, encoding="utf-8",
            stdout=PIPE, stderr=PIPE, check=True)
    except CalledProcessError as err:
        return (err.stderr or "").strip() or f"pass exited with status {err.returncode}"
    except OSError as err:
        return str(err)
    return None


def warn_case_collisions(paths: List[str]) -> None:
    seen: Dict[str, str] = {}
    for path in sorted(paths):
        key = path.casefold()
        if key in seen:
            warn(f"paths differ only by case (collide on case-insensitive filesystems): "
                 f"{seen[key]} / {path}")
        seen[key] = path


def import_entries(entries: Dict[str, str], overwrite: bool,
                   dry_run: bool) -> Tuple[int, int, List[str]]:
    """Returns (imported, skipped, failed paths)."""
    store = store_dir()
    imported = 0
    skipped = 0
    failed: List[str] = []

    for path, data in sorted(entries.items()):
        if not overwrite and (store / f"{path}.gpg").exists():
            print(f"[SKIP] {path} (already exists; use --overwrite)")
            skipped += 1
        elif dry_run:
            print(f"[DRY ] {path}")
            imported += 1
        else:
            reason = pass_insert(path, data)
            if reason is None:
                print(f"[ OK ] {path}")
                imported += 1
            else:
                print(f"[FAIL] {path}: {reason}", file=sys.stderr)
                failed.append(path)
    return imported, skipped, failed


def run_import(args: argparse.Namespace) -> int:
    if not args.dry_run:
        if shutil.which("pass") is None:
            error("'pass' was not found in PATH")
            return 1
        if not (store_dir() / ".gpg-id").exists():
            error(f"password store is not initialised ({store_dir() / '.gpg-id'} missing); "
                  "run: pass init <gpg-id>")
            return 1

    entries = load_entries(args.file, args.root, args.duplicates, args.include_recycle_bin)
    if entries is None:
        return 1
    if not entries:
        info("nothing to import")
        return 0

    warn_case_collisions(list(entries))
    imported, skipped, failed = import_entries(entries, args.overwrite, args.dry_run)

    verb = "would be imported" if args.dry_run else "imported"
    print(f"[ OK ] Done: {imported} {verb}, {skipped} skipped, {len(failed)} failed "
          f"(of {len(entries)}).")
    if failed:
        error("failed entries:\n  " + "\n  ".join(failed))
        return 1
    return 0


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)  # keep stdout/stderr in order # type: ignore
    parser = argparse.ArgumentParser(
        description="Import a KeePass2 XML export into pass (password-store)."
    )
    parser.add_argument("-f", "--file", required=True,
                        help="path to the KeePass2 XML export")
    parser.add_argument("-r", "--root", default=None,
                        help="replace the KeePass root group name with this folder "
                             "(use '' for a flat structure)")
    parser.add_argument("--duplicates", choices=("ask", "merge", "split"), default="ask",
                        help="what to do when two entries get the same path (default: ask)")
    parser.add_argument("--overwrite", action="store_true",
                        help="overwrite entries that already exist in the store "
                             "(default: skip them)")
    parser.add_argument("--include-recycle-bin", action="store_true",
                        help="also import the KeePass Recycle Bin")
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="print what would be done, change nothing")
    return run_import(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
