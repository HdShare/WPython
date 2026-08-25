import mmap
import re
import sys
from pathlib import Path

DLL_DIR = Path("dll")
SIGNATURE = """
?? ??
0F 85 D1 F9 FF FF
48 8B 95 30 02 00 00
48 8D 8D E0 00 00 00
E8 ?? ?? ?? ??
90
48 8D 8E F0 01 00 00
48 8D BD E0 00 00 00
48 89 FA
E8 ?? ?? ?? ??
"""
PATCH_OFFSET = 0
EXPECTED = bytes.fromhex("84 C0")
REPLACEMENT = bytes.fromhex("B0 01")
PATTERN = re.compile(
    b"".join(
        b"." if token in {"?", "??"} else re.escape(bytes.fromhex(token))
        for token in SIGNATURE.split()
    ),
    re.DOTALL,
)


def patch(dll: Path) -> str:
    try:
        with dll.open("rb") as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
            match = PATTERN.search(data)
            if match is None:
                raise ValueError("未找到特征")

            match_offset = match.start()
            patch_offset = match_offset + PATCH_OFFSET
            current = data[patch_offset:patch_offset + len(EXPECTED)]
            if current == REPLACEMENT:
                print(f"无需处理: {dll}")
                return "skipped"
            if current != EXPECTED:
                raise ValueError("预期不匹配")

        backup = Path(f"{dll}.bak")
        with dll.open("rb") as source, backup.open("xb") as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)

        with dll.open("r+b") as file:
            file.seek(patch_offset)
            file.write(REPLACEMENT)

        print(f"补丁完成: 文件: {dll} | 特征: 0x{match_offset:X} | 补丁: 0x{patch_offset:X} | 备份: {backup}")
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
        key=lambda path: path.name.casefold(),
    )

    results = [patch(dll) for dll in dlls]
    patched = results.count("patched")
    skipped = results.count("skipped")
    failed = results.count("failed")
    print(f"处理完成: 总数: {len(dlls)} | 已处理: {patched} | 无需处理: {skipped} | 失败: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
