"""Write an InferredPackage out to disk in Escher ADK package layout."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from .ingest import SkillCorpus
from .models import InferredPackage


def write_package(inferred: InferredPackage, corpus: SkillCorpus, out_dir: Path) -> Path:
    """Write package files to out_dir / <agent_id>/. Returns the package directory.

    The .py source file for each tool is copied from the originating skill directory in
    the corpus (located via inferred_tool.source_skill_name + source_filename) — the LLM
    does not regenerate it.
    """
    pkg_dir = out_dir / inferred.agent_registry.agent_id
    if pkg_dir.exists():
        shutil.rmtree(pkg_dir)
    pkg_dir.mkdir(parents=True)

    _write_json(pkg_dir / "agent_registry.json", inferred.agent_registry.model_dump(mode="json"))

    skills_dir = pkg_dir / "skills"
    skills_dir.mkdir()
    for skill in inferred.skills:
        _write_json(skills_dir / f"{skill.skill_id}.json", skill.model_dump(mode="json"))

    tools_dir = pkg_dir / "tools"
    tools_dir.mkdir()
    skill_index = {s.name: s for s in corpus.skills}
    for itool in inferred.tools:
        tool_subdir = tools_dir / itool.spec.tool_id
        tool_subdir.mkdir()
        _write_json(tool_subdir / f"{itool.spec.tool_id}.json", itool.spec.model_dump(mode="json"))
        _copy_tool_source(itool, skill_index, tool_subdir)

    if inferred.guardrails:
        guard_dir = pkg_dir / "guardrails"
        guard_dir.mkdir()
        for guard in inferred.guardrails:
            _write_json(guard_dir / f"{guard.guardrail_id}.json", guard.model_dump(mode="json"))

    return pkg_dir


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _copy_tool_source(itool, skill_index, tool_subdir: Path) -> None:
    skill = skill_index.get(itool.source_skill_name)
    if skill is None:
        raise RuntimeError(
            f"tool {itool.spec.tool_id} references skill '{itool.source_skill_name}' "
            f"which is not in the corpus. Available: {list(skill_index)}"
        )
    match = next((f for f in skill.files if f.relpath == itool.source_filename), None)
    if match is None:
        raise RuntimeError(
            f"tool {itool.spec.tool_id} references file '{itool.source_filename}' "
            f"which is not in skill '{itool.source_skill_name}'. "
            f"Files: {[f.relpath for f in skill.files]}"
        )
    out = tool_subdir / itool.spec.source_code.filename
    out.write_text(match.content, encoding="utf-8")
