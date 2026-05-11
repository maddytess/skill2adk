"""Read agentskills.io / Anthropic SKILL.md skills from a local path or a GitHub URL.

A skill is a directory containing `SKILL.md` (YAML frontmatter + markdown body) plus
optional sibling files (`scripts/`, `references/`, etc.). This module walks one or more
skill directories and produces a `SkillCorpus` — the raw input for LLM-based inference.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import yaml

# Cap any single attached file at 64KB to keep prompts tractable.
MAX_FILE_BYTES = 64 * 1024
SKILL_FILENAME = "SKILL.md"
FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)


@dataclass
class SkillFile:
    relpath: str
    content: str
    is_executable: bool


@dataclass
class SourceSkill:
    """One SKILL.md plus its sibling files, parsed from disk."""

    name: str
    skill_dir: str
    frontmatter: dict
    body: str
    files: list[SkillFile] = field(default_factory=list)


@dataclass
class SkillCorpus:
    """All skill content the converter has to draw from."""

    source: str
    skills: list[SourceSkill] = field(default_factory=list)


def ingest(source: str) -> SkillCorpus:
    """Load skills from a local directory or `https://github.com/owner/repo[/path]` URL."""
    if source.startswith(("http://", "https://", "git@")):
        return _ingest_github(source)
    return _ingest_local(Path(source).expanduser().resolve())


def _ingest_local(root: Path) -> SkillCorpus:
    if not root.exists():
        raise FileNotFoundError(root)
    skills = list(_collect_skills(root))
    if not skills:
        raise ValueError(f"no SKILL.md files found under {root}")
    return SkillCorpus(source=str(root), skills=skills)


def _ingest_github(url: str) -> SkillCorpus:
    """Clone a github repo (or subpath) into a temp dir and ingest."""
    repo_url, subpath = _parse_github_url(url)
    tmp = Path(tempfile.mkdtemp(prefix="skill2adk-"))
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(tmp)],
            check=True, capture_output=True, text=True,
        )
        target = tmp / subpath if subpath else tmp
        if not target.exists():
            raise FileNotFoundError(f"{subpath} not found in {repo_url}")
        skills = list(_collect_skills(target))
        if not skills:
            raise ValueError(f"no SKILL.md files found under {url}")
        return SkillCorpus(source=url, skills=skills)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _parse_github_url(url: str) -> tuple[str, Optional[str]]:
    """Split a github URL into (clone_url, subpath_inside_repo)."""
    parsed = urlparse(url)
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise ValueError(f"can't parse github URL: {url}")
    owner, repo = parts[0], parts[1].removesuffix(".git")
    clone = f"https://github.com/{owner}/{repo}.git"
    # /tree/<branch>/<sub>... or /blob/<branch>/<sub>...
    if len(parts) > 4 and parts[2] in ("tree", "blob"):
        return clone, "/".join(parts[4:])
    if len(parts) > 2:
        return clone, "/".join(parts[2:])
    return clone, None


def _collect_skills(root: Path):
    """Yield SourceSkill objects for every SKILL.md found under root."""
    if (root / SKILL_FILENAME).exists():
        yield _load_skill(root)
        return
    for skill_md in sorted(root.rglob(SKILL_FILENAME)):
        yield _load_skill(skill_md.parent)


def _load_skill(skill_dir: Path) -> SourceSkill:
    skill_md = skill_dir / SKILL_FILENAME
    text = skill_md.read_text(encoding="utf-8")
    match = FRONTMATTER_RE.match(text)
    if not match:
        raise ValueError(f"{skill_md} is missing YAML frontmatter")
    frontmatter = yaml.safe_load(match.group(1)) or {}
    body = match.group(2)

    files: list[SkillFile] = []
    for path in sorted(skill_dir.rglob("*")):
        if not path.is_file() or path.name == SKILL_FILENAME:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if len(content) > MAX_FILE_BYTES:
            content = content[:MAX_FILE_BYTES] + "\n... [truncated]"
        rel = path.relative_to(skill_dir).as_posix()
        files.append(SkillFile(
            relpath=rel,
            content=content,
            is_executable=path.suffix in {".py", ".js", ".ts", ".sh", ".go"},
        ))

    return SourceSkill(
        name=frontmatter.get("name") or skill_dir.name,
        skill_dir=skill_dir.name,
        frontmatter=frontmatter,
        body=body,
        files=files,
    )
