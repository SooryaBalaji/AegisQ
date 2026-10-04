"""Record every proposed patch on its own git branch, without touching any working tree.

Uses git plumbing (hash-object / mktree / commit-tree / update-ref) in a bare
repository inside the workspace, so the branch shows the original config as
the parent commit and the patched config as the child: ``git diff`` on the
branch is exactly the proposed change.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from aegisq.proc import run_sync

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


class PatchStore:
    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self.git = shutil.which("git")
        self.enabled = self.git is not None
        if self.enabled and not (repo / "HEAD").exists():
            repo.mkdir(parents=True, exist_ok=True)
            res = self._git("init", "--bare", "--quiet", str(repo), use_dir=False)
            self.enabled = res is not None

    def _git(self, *args: str, stdin: bytes | None = None, use_dir: bool = True) -> str | None:
        assert self.git
        env_args = ["-c", "user.name=AegisQ Agent", "-c", "user.email=aegisq@localhost"]
        argv = [self.git, *env_args, *(["--git-dir", str(self.repo)] if use_dir else []), *args]
        res = run_sync(argv, timeout=30, stdin_data=stdin)
        return res.stdout.strip() if res.ok else None

    def _blob(self, data: str) -> str | None:
        return self._git("hash-object", "-w", "--stdin", stdin=data.encode())

    def _tree(self, entries: dict[str, str]) -> str | None:
        lines = "".join(f"100644 blob {sha}\t{name}\n" for name, sha in sorted(entries.items()))
        return self._git("mktree", stdin=lines.encode())

    def record(
        self, service: str, proposal_id: str, filename: str, original: str, patched: str, diff: str, message: str
    ) -> str | None:
        """Returns the branch name, or None when git is unavailable."""
        if not self.enabled:
            return None
        fname = _SAFE.sub("_", Path(filename).name) or "nginx.conf"
        b_orig, b_new, b_diff = self._blob(original), self._blob(patched), self._blob(diff)
        if not (b_orig and b_new and b_diff):
            return None
        t_orig = self._tree({fname: b_orig})
        t_new = self._tree({fname: b_new, "patch.diff": b_diff})
        if not (t_orig and t_new):
            return None
        c_orig = self._git("commit-tree", t_orig, "-m", f"{service}: config before AegisQ proposal {proposal_id}")
        if not c_orig:
            return None
        c_new = self._git("commit-tree", t_new, "-p", c_orig, "-m", message)
        if not c_new:
            return None
        branch = f"aegisq/{_SAFE.sub('-', service)}/{proposal_id}"
        if self._git("update-ref", f"refs/heads/{branch}", c_new) is None:
            return None
        return branch
