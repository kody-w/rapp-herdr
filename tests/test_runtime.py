from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapp_herdr.manager import (
    _default_brainstem_python,
    _powershell_command,
    _requirements_fingerprint,
    prepare_brainstem_python,
)
from rapp_herdr.model import RappHerdrError, load_neighborhood, resolve_topology

from tests.helpers import create_neighborhood, create_twin


class RuntimePreparationTests(unittest.TestCase):
    def _topology(self, root: Path):
        manifest, rappids = create_neighborhood(root / "neighborhood", count=1)
        estate = root / "estate"
        workspace = create_twin(estate, "selected", rappids[0])
        topology = resolve_topology(
            load_neighborhood(manifest),
            [estate],
            require_all_local=True,
        )
        return topology, workspace

    def test_top_level_requirements_is_the_canonical_dependency_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            topology, workspace = self._topology(Path(directory))

            self.assertEqual(
                topology.twins[0].requirements,
                (workspace / "requirements.txt").resolve(),
            )

    def test_default_venv_is_keyed_by_complete_requirements_fingerprint(self) -> None:
        first = _default_brainstem_python("a" * 64)
        second = _default_brainstem_python("b" * 64)

        self.assertNotEqual(first, second)
        self.assertIn("a" * 32, str(first))
        self.assertIn("b" * 32, str(second))

    def test_configured_venv_python_preserves_symlink_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            topology, _workspace = self._topology(root)
            python = root / "venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.symlink_to(sys.executable)

            with patch(
                "rapp_herdr.manager._prepare_brainstem_python_locked",
                return_value=python.absolute(),
            ) as prepare:
                result = prepare_brainstem_python(
                    topology,
                    configured_python=python,
                    bootstrap=False,
                )

            self.assertEqual(result, python.absolute())
            self.assertEqual(prepare.call_args.args[0], python.absolute())
            self.assertNotEqual(prepare.call_args.args[0], python.resolve())

    def test_included_requirements_are_rejected_before_environment_sharing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            requirements = Path(directory) / "requirements.txt"
            requirements.write_text("-r deps.txt\nFlask>=3\n", encoding="utf-8")

            with self.assertRaisesRegex(RappHerdrError, "self-contained"):
                _requirements_fingerprint(requirements)

    def test_local_requirement_is_rejected_before_environment_sharing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            requirements = Path(directory) / "requirements.txt"
            requirements.write_text(
                "private-package @ file:../private-package\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RappHerdrError, "self-contained"):
                _requirements_fingerprint(requirements)

    def test_windows_launcher_contains_only_encoded_untrusted_arguments(self) -> None:
        arguments = [
            r"C:\Program Files\Python311\python.exe",
            "-c",
            "print('safe')",
            r"C:\Twin Neighborhood\O'Brien & Sons",
            "Scout&calc.exe",
        ]

        command = _powershell_command(arguments)

        for value in arguments:
            self.assertNotIn(value, command)
        encoded_script = command.rsplit(" ", 1)[-1]
        script = base64.b64decode(encoded_script).decode("utf-16le")
        match = re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", script)
        self.assertIsNotNone(match)
        payload = json.loads(base64.b64decode(match.group(1)))
        self.assertEqual(payload["executable"], arguments[0])
        self.assertEqual(payload["arguments"], arguments[1:])

    @unittest.skipUnless(os.name == "nt", "PowerShell execution is Windows-only")
    def test_windows_launcher_round_trips_metacharacters(self) -> None:
        marker = "Scout&calc.exe 'quoted' ^ %PATH%"
        command = _powershell_command(
            [
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1])",
                marker,
            ]
        )

        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), marker)

    @patch("rapp_herdr.manager._runtime_imports_work", return_value=True)
    @patch("rapp_herdr.manager.subprocess.run")
    def test_bootstrap_installs_complete_declared_requirements(
        self, run, _imports
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            topology, _ = self._topology(root)
            python = root / "python"
            python.write_text("", encoding="utf-8")
            run.return_value = subprocess.CompletedProcess([], 0, "", "")

            selected = prepare_brainstem_python(
                topology,
                configured_python=python,
                bootstrap=True,
            )

            self.assertEqual(selected, python.absolute())
            command = run.call_args.args[0]
            self.assertEqual(command[1:4], ["-m", "pip", "install"])
            self.assertIn("-r", command)
            self.assertIn(str(topology.twins[0].requirements), command)

    @patch("rapp_herdr.manager._runtime_imports_work", return_value=True)
    @patch(
        "rapp_herdr.manager._requirements_satisfied",
        return_value=(False, ("pyzipper",)),
    )
    def test_no_bootstrap_rejects_missing_declared_dependency(
        self, _requirements, _imports
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            topology, _ = self._topology(root)
            python = root / "python"
            python.write_text("", encoding="utf-8")

            with self.assertRaisesRegex(RappHerdrError, "pyzipper"):
                prepare_brainstem_python(
                    topology,
                    configured_python=python,
                    bootstrap=False,
                )


if __name__ == "__main__":
    unittest.main()
