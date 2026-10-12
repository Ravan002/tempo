import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("prepare_reth_update", ROOT / "scripts/prepare_reth_update.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)

NEW, OLD = "1" * 40, "2" * 40
MANIFEST = '''[workspace.dependencies]
node = { git = "https://github.com/paradigmxyz/reth", rev = "2222222", features = ["default"] }
'''


class AdapterTests(unittest.TestCase):
    def responses(self, prior=OLD):
        return [{"sha": NEW}, {"content": base64.b64encode(MANIFEST.encode()).decode()}, {"sha": prior}]

    def test_resolves_short_baseline_and_freezes_full_upstream_sha(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "tempoxyz/tempo", "UPDATE_REQUESTED_REF": "main"}), \
             patch.object(adapter, "api", side_effect=self.responses()) as api:
            plan = adapter.resolve()
        self.assertEqual(plan["pins"], {adapter.URL: NEW})
        self.assertEqual(plan["branch"], "reth-auto-bump")
        self.assertEqual(plan["closed_pr_policy"], "new-pr")
        self.assertIn(OLD + "..." + NEW, plan["body"])
        self.assertEqual(api.call_args.args[0], "repos/paradigmxyz/reth/commits/2222222")

    def test_already_current_main_is_noop(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "tempoxyz/tempo", "UPDATE_REQUESTED_REF": "main"}), \
             patch.object(adapter, "api", side_effect=self.responses(NEW)):
            self.assertEqual(adapter.resolve(), {"schema_version": 1, "skip": True})

    def test_wrong_repository_or_manual_downgrade_ref_is_rejected(self):
        for repo, ref in (("example/fork", "main"), ("tempoxyz/tempo", "v1.0.0")):
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": repo, "UPDATE_REQUESTED_REF": ref}), \
                 patch.object(adapter, "api") as api:
                with self.assertRaises(ValueError):
                    adapter.resolve()
                api.assert_not_called()

    def test_inconsistent_baseline_revisions_fail(self):
        manifest = MANIFEST + 'other = { git="https://github.com/paradigmxyz/reth", rev="3333333" }\n'
        responses = [{"sha": NEW}, {"content": base64.b64encode(manifest.encode()).decode()}]
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "tempoxyz/tempo", "UPDATE_REQUESTED_REF": "main"}), \
             patch.object(adapter, "api", side_effect=responses):
            with self.assertRaisesRegex(ValueError, "one current"):
                adapter.resolve()

    def test_invalid_upstream_revision_fails(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "tempoxyz/tempo", "UPDATE_REQUESTED_REF": "main"}), \
             patch.object(adapter, "api", return_value={"sha": "main"}):
            with self.assertRaisesRegex(ValueError, "full commit"):
                adapter.resolve()

    def test_updates_workspace_development_and_alias_pins_without_changing_comments(self):
        text = MANIFEST + '''# example = { git="https://github.com/paradigmxyz/reth", rev="aaaaaaa" }
[dev-dependencies]
types = {git='https://github.com/paradigmxyz/reth.git', rev='2222222', features=['tests']}
other = {git="https://github.com/example/other", rev="aaaaaaa"}
'''
        bumped = adapter.bump(text, NEW)
        self.assertEqual(adapter.revisions(tomllib.loads(bumped)), [NEW, NEW])
        self.assertIn("features=['tests']", bumped)
        self.assertIn('other = {git="https://github.com/example/other", rev="aaaaaaa"}', bumped)
        self.assertIn('# example = { git="https://github.com/paradigmxyz/reth", rev="aaaaaaa" }', bumped)
        self.assertEqual(adapter.bump(bumped, NEW), bumped)

    def test_unsupported_layout_fails_instead_of_silently_missing_pin(self):
        text = MANIFEST.replace('git = "https://github.com/paradigmxyz/reth", rev = "2222222"',
                                'rev = "2222222", git = "https://github.com/paradigmxyz/reth"')
        with self.assertRaisesRegex(ValueError, "partial bump"):
            adapter.bump(text, NEW)

    def test_apply_uses_frozen_plan_and_covers_nested_manifests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text(MANIFEST)
            (root / "crates/example").mkdir(parents=True)
            (root / "crates/example/Cargo.toml").write_text(MANIFEST)
            with patch.object(adapter, "api") as api:
                adapter.apply({"schema_version": 1, "pins": {adapter.URL: NEW}}, root)
                api.assert_not_called()
            for file in root.rglob("Cargo.toml"):
                self.assertEqual(adapter.revisions(tomllib.loads(file.read_text())), [NEW])
            self.assertFalse((root / "Cargo.lock").exists())

    def test_apply_rejects_wrong_source_missing_pins_and_mutable_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pins in ({"https://github.com/example/other": NEW}, {adapter.URL: "main"}):
                with self.assertRaises(ValueError):
                    adapter.apply({"schema_version": 1, "pins": pins}, root)
            with self.assertRaisesRegex(ValueError, "no reth"):
                adapter.apply({"schema_version": 1, "pins": {adapter.URL: NEW}}, root)

    def test_current_repository_manifest_remains_valid_and_preserves_features(self):
        current = (ROOT / "Cargo.toml").read_text()
        updated = adapter.bump(current, NEW)
        before, after = tomllib.loads(current), tomllib.loads(updated)
        self.assertTrue(adapter.revisions(after))
        self.assertEqual(set(adapter.revisions(after)), {NEW})
        for name, dependency in before["workspace"]["dependencies"].items():
            if isinstance(dependency, dict) and dependency.get("git") == adapter.URL:
                expected = dependency | {"rev": NEW}
                self.assertEqual(after["workspace"]["dependencies"][name], expected)


if __name__ == "__main__":
    unittest.main()
