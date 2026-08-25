import mmap
import re
import sys
from pathlib import Path

DLL_DIR = Path("dll")
RULES = (
    {
        "signature": "?? ?? 0F 85 ?? ?? FF FF 48 8B 95 30 02 00 00 48 8D 8D E0 00 00 00 E8 ?? ?? ?? ?? 48 8D 8E ?? ?? 00 00 48 8D BD E0 00 00 00 48 89 FA E8 ?? ?? ?? ??",
        "offset": 0,
        "expected": bytes.fromhex("84 C0"),
        "replacement": bytes.fromhex("B0 01"),
    },
    {
        "signature": "?? ?? 0F 85 ?? ?? FF FF 48 8B 95 30 02 00 00 48 8D 8D E0 00 00 00 E8 ?? ?? ?? ?? 90 48 8D 8E ?? ?? 00 00 48 8D BD E0 00 00 00 48 89 FA E8 ?? ?? ?? ??",
        "offset": 0,
        "expected": bytes.fromhex("84 C0"),
        "replacement": bytes.fromhex("B0 01"),
    },
)

PATTERNS = tuple(
    re.compile(
        b"".join(
            b"." if token in {"?", "??"} else re.escape(bytes.fromhex(token))
            for token in rule["signature"].split()
        ),
        re.DOTALL,
    )
    for rule in RULES
)


def patch(dll: Path) -> str:
    try:
        with dll.open("rb") as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
            matched = False
            for rule_number, (rule, pattern) in enumerate(zip(RULES, PATTERNS), 1):
                match = pattern.search(data)
                if match is None:
                    continue

                matched = True
                match_offset = match.start()
                patch_offset = match_offset + rule["offset"]
                current = data[patch_offset:patch_offset + len(rule["expected"])]
                if current == rule["replacement"]:
                    print(f"无需处理: {dll} | 规则: {rule_number}")
                    return "skipped"
                if current == rule["expected"]:
                    break
            else:
                raise ValueError("预期不匹配" if matched else "未找到特征")

        backup = Path(f"{dll}.bak")
        with dll.open("rb") as source, backup.open("xb") as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)

        with dll.open("r+b") as file:
            file.seek(patch_offset)
            file.write(rule["replacement"])

        print(f"补丁完成: 文件: {dll} | 规则: {rule_number} | 特征: 0x{match_offset:X} | 补丁: 0x{patch_offset:X}")
        return "patched"
    except (OSError, ValueError) as error:
        print(f"失败: {dll} | {error}", file=sys.stderr)
        return "failed"


def main() -> int:
    DLL_DIR.mkdir(exist_ok=True)
    dlls = sorted(
        (
            path
            for path in DLL_DIR.iterdir()
            if path.is_file() and path.suffix.casefold() == ".dll"
        ),
        key=lambda path: tuple(
            (0, int(part)) if part.isdigit() else (1, part.casefold())
            for part in re.split(r"([0-9]+)", path.name)
        ),
    )

    results = [patch(dll) for dll in dlls]
    patched = results.count("patched")
    skipped = results.count("skipped")
    failed = results.count("failed")
    print(f"处理完成: 总数: {len(dlls)} | 已处理: {patched} | 无需处理: {skipped} | 失败: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
