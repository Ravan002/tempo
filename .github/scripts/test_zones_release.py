"""Exercise the release workflow's tag parsing and package-version check."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.safe_load((ROOT / '.github/workflows/zones-release.yml').read_text())
PROFILING_WORKFLOW = yaml.safe_load((ROOT / '.github/workflows/zones-docker-profiling.yml').read_text())


def script(job, name):
    return next(step['run'] for step in WORKFLOW['jobs'][job]['steps']
                if step.get('name') == name)


class ZonesReleaseTests(unittest.TestCase):
    def parse_tag(self, tag, dispatch=True):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(['git', 'init', '-q', tmp], check=True)
            subprocess.run(['git', '-C', tmp, 'config', 'user.name', 'Test'], check=True)
            subprocess.run(['git', '-C', tmp, 'config', 'user.email', 'test@example.invalid'], check=True)
            (Path(tmp) / 'source').write_text('release\n')
            subprocess.run(['git', '-C', tmp, 'add', '.'], check=True)
            subprocess.run(['git', '-C', tmp, 'commit', '-qm', 'release'], check=True)
            if tag in ('zones/v0.3.5', 'zones/v0.3.5-rc.1'):
                subprocess.run(['git', '-C', tmp, 'tag', tag], check=True)
            sha = subprocess.check_output(['git', '-C', tmp, 'rev-parse', 'HEAD'], text=True).strip()
            output = Path(tmp) / 'output'
            result = subprocess.run(['bash', '-eu', '-c', script('get-version', 'Get version from tag')],
                                    cwd=tmp,
                                    env=dict(os.environ, INPUT_TAG=tag if dispatch else '',
                                             GITHUB_REF=f'refs/tags/{tag}', GITHUB_OUTPUT=str(output)),
                                    text=True, capture_output=True)
            return result.returncode, output.read_text() if output.exists() else '', sha

    def test_zones_tags_keep_separate_ref_and_filename_version(self):
        for tag in ('zones/v0.3.5', 'zones/v0.3.5-rc.1'):
            for dispatch in (True, False):
                with self.subTest(tag=tag, dispatch=dispatch):
                    code, output, sha = self.parse_tag(tag, dispatch)
                    self.assertEqual(code, 0)
                    self.assertEqual(output, f'tag={tag}\nversion={tag[6:]}\ncommit_sha={sha}\n')

    def test_rejects_tempo_tags_branches_and_invalid_versions(self):
        for tag in ('v1.16.0', 'main', 'zones/main', 'zones/v0.3', 'zones/v0.3.5/other',
                    'zones/v0.3.5\ntag=other'):
            with self.subTest(tag=tag):
                code, output, _ = self.parse_tag(tag)
                self.assertNotEqual(code, 0)
                self.assertEqual(output, '')

    def test_release_jobs_check_out_resolved_commit(self):
        for job in ('check-version', 'build-release', 'create-release'):
            with self.subTest(job=job):
                checkout = next(step for step in WORKFLOW['jobs'][job]['steps']
                                if step.get('uses', '').startswith('actions/checkout@'))
                self.assertEqual(checkout['with']['ref'],
                                 '${{ needs.get-version.outputs.commit_sha }}')

    def test_profiling_cannot_select_a_release_tag(self):
        dispatch = PROFILING_WORKFLOW.get('on', PROFILING_WORKFLOW.get(True))['workflow_dispatch']
        self.assertNotIn('inputs', dispatch or {})
        metadata = next(step for step in PROFILING_WORKFLOW['jobs']['build-and-push']['steps']
                        if step.get('id') == 'meta-tempo-zone')
        self.assertEqual(metadata['with']['tags'].splitlines(),
                         ['type=raw,value=profiling', 'type=sha,prefix=profiling-sha-'])

    def test_selects_zones_package_and_rejects_version_prefix_collisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            cargo = Path(tmp) / 'cargo'
            cargo.write_text('#!/bin/sh\nprintf \'%s\\n\' \'{"packages":['
                             '{"name":"tempo","version":"1.16.0"},'
                             '{"name":"tempo-zone","version":"0.3.5"}]}\'\n')
            cargo.chmod(0o755)
            for version, allowed in (('v0.3.5', True), ('v0.3.5-rc.1', True),
                                     ('v0.3.50', False), ('v1.16.0', False)):
                with self.subTest(version=version):
                    result = subprocess.run(['bash', '-eu', '-c',
                                             script('check-version', 'Verify crate version matches tag')],
                                            env=dict(os.environ, VERSION=version,
                                                     PATH=f'{tmp}:{os.environ["PATH"]}'),
                                            capture_output=True)
                    self.assertEqual(result.returncode == 0, allowed)

    def test_all_accepted_prerelease_suffixes_create_prerelease_drafts(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = Path(tmp) / 'gh'
            gh.write_text('#!/bin/sh\n'
                          'if [ "$1" = api ]; then\n'
                          '  printf \'{"type":"commit","sha":"%s"}\\n\' "$REMOTE_SHA"\n'
                          'else\n'
                          '  printf \'%s\\n\' "$@" > "$ARGS_FILE"\n'
                          'fi\n')
            gh.chmod(0o755)
            args = Path(tmp) / 'args'
            for version in ('v0.3.5', 'v0.3.5-rc.1', 'v0.3.5-preview.1'):
                with self.subTest(version=version):
                    subprocess.run(['bash', '-eu', '-c', script('create-release', 'Create Release')
                                    .replace('${{ github.repository }}', 'tempoxyz/tempo')],
                                   env=dict(os.environ, VERSION=version, TAG='zones/' + version,
                                            COMMIT_SHA='a' * 40, REMOTE_SHA='a' * 40,
                                            GITHUB_REPOSITORY='tempoxyz/tempo',
                                            ARGS_FILE=str(args), PATH=f'{tmp}:{os.environ["PATH"]}'),
                                   check=True, capture_output=True)
                    self.assertEqual('--prerelease' in args.read_text().splitlines(), '-' in version)
                    self.assertIn('--verify-tag', args.read_text().splitlines())

            result = subprocess.run(['bash', '-eu', '-c', script('create-release', 'Create Release')
                                     .replace('${{ github.repository }}', 'tempoxyz/tempo')],
                                    env=dict(os.environ, VERSION='v0.3.5', TAG='zones/v0.3.5',
                                             COMMIT_SHA='a' * 40, REMOTE_SHA='b' * 40,
                                             GITHUB_REPOSITORY='tempoxyz/tempo',
                                             ARGS_FILE=str(args), PATH=f'{tmp}:{os.environ["PATH"]}'),
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)
