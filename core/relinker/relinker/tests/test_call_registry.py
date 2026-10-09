import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from test_string_table_bounds import fixture
from test_guest_intel_trampolines import main_fixture
from test_guest_module_directories import module_with_symbol


def main():
    relinker = Path(sys.argv[1]).resolve()
    names = ["symbol", 'quote"slash\\', "caf\u00e9-\u007f"]
    names.extend("symbol" + chr(value) for value in range(1, 32))
    with tempfile.TemporaryDirectory(prefix="anyps5-call-registry-") as directory:
        work = Path(directory)
        for index, name in enumerate(names):
            strings = b"\0lib.so\0" + name.encode("utf-8") + b"\0"
            image = fixture(str_size=len(strings), table_bytes=strings)
            struct.pack_into("<H", image, 56, 5)
            for slot in (3, 4):
                struct.pack_into("<IIQQQQQQ", image, 64 + slot * 56,
                                 0x6fffff01, 0, 0, 0, 0, 0, 0, 1)
            source = work / (str(index) + ".elf")
            source.write_bytes(image)
            for options in ([], ["--windows"]):
                output = work / (str(index) + ("-windows.exe" if options else "-linux.out"))
                result = subprocess.run([str(relinker), "--skip-sce-module", "--registry", *options,
                                         str(source), str(output)], capture_output=True, text=True, timeout=20)
                if result.returncode != 0 or not output.exists():
                    raise AssertionError((name, options, result.returncode, result.stdout, result.stderr))
                registry = output.with_suffix(".registry.json")
                entries = json.loads(registry.read_text(encoding="utf-8"))
                expected = [{"nid": name, "library": "", "relocationType": "R_X86_64_GLOB_DAT",
                             "relocationOffset": "0x700", "targetSection": ".got", "targetOffset": "0x300",
                             "callSites": ["0x200"], "callSitesResolved": True}]
                if entries != expected:
                    raise AssertionError((name, options, entries))

        image = fixture()
        struct.pack_into("<H", image, 56, 5)
        for slot in (3, 4):
            struct.pack_into("<IIQQQQQQ", image, 64 + slot * 56,
                             0x6fffff01, 0, 0, 0, 0, 0, 0, 1)
        original = bytes(image)

        def reject_collision(source, output, alias=None):
            source.write_bytes(original)
            if alias is not None:
                os.link(source, alias)
            result = subprocess.run([str(relinker), "--skip-sce-module", "--registry",
                                     str(source), str(output)], capture_output=True, text=True, timeout=20)
            if (result.returncode != 2 or "Call registry output would overwrite the input file" not in result.stderr
                    or source.read_bytes() != original or (alias is not None and alias.read_bytes() != original)
                    or output.exists()):
                raise AssertionError((source, alias, result.returncode, result.stdout, result.stderr))

        direct_source = work / "direct.registry.json"
        reject_collision(direct_source, work / "direct")

        hardlink_source = work / "hardlink-input.elf"
        hardlink_alias = work / "hardlink.registry.json"
        reject_collision(hardlink_source, work / "hardlink", hardlink_alias)

        for windows in (False, True):
            for alias in (False, True):
                case = work / f"module-{windows}-{alias}"
                module_dir = case / "sce_module"
                module_dir.mkdir(parents=True)
                executable = case / "eboot.bin"
                executable.write_bytes(main_fixture())
                module_source = module_dir / ("provider.prx" if alias else "module.registry.json")
                module_source.write_bytes(module_with_symbol(True))
                registry_source = module_dir / "module.registry.json"
                if alias:
                    os.link(module_source, registry_source)
                output = module_dir / ("module.exe" if windows else "module")
                options = ["--windows"] if windows else []
                result = subprocess.run([str(relinker), "--registry", *options,
                                         str(executable), str(output)], capture_output=True, text=True, timeout=20)
                if (result.returncode != 2 or "would overwrite a guest module input" not in result.stderr
                        or executable.read_bytes() != main_fixture() or module_source.read_bytes() != module_with_symbol(True)
                        or (alias and registry_source.read_bytes() != module_with_symbol(True))
                        or output.exists() or (case / "app0").exists()):
                    raise AssertionError((windows, alias, result.returncode, result.stdout, result.stderr))
    print("Call registry JSON tests passed")


if __name__ == "__main__":
    main()
