"""LLM-driven inference: SkillCorpus -> InferredPackage.

Strategy
--------
The full InferredPackage schema is too large for Anthropic's structured-output grammar
compiler ("compiled grammar is too large"). We split it:

  1. One strict call returns a PackagePlan — a tiny inventory of IDs and source mappings.
  2. One strict call per document expands each plan entry:
       - 1 call for the AgentRegistry
       - 1 call per Skill
       - 1 call per Tool (each tool_id mapped to one source script in the corpus)
       - 1 call per Guardrail

Every call uses `client.messages.parse(output_format=...)` with strict pydantic
validation. The frozen system prompt (rules + spec + reference packages) is marked
cacheable, so repeat calls within the same package — and across packages — hit the
prompt cache. Each call retries up to N times on validation failure, replaying the
error text back to the model as feedback.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, TypeVar

import anthropic
from pydantic import BaseModel, ValidationError

from .ingest import SkillCorpus, SourceSkill
from .models import (
    AgentRegistry,
    ExecutionPlan,
    Guardrail,
    GuardrailPlan,
    InferredPackage,
    InferredTool,
    PackagePlan,
    Skill,
    SkillBody,
    SkillPlan,
    Tool,
    ToolPlan,
)

T = TypeVar("T", bound=BaseModel)

MODEL = "claude-opus-4-7"
DEFAULT_MAX_RETRIES = 3
SPEC_PATH = Path(__file__).resolve().parent.parent / "spec" / "package_format.md"
REFERENCE_DIR = Path(__file__).resolve().parent.parent / "escher-adk-packages"


@dataclass
class InferenceConfig:
    domain: str
    api_key: Optional[str] = None
    max_retries: int = DEFAULT_MAX_RETRIES
    verbose: bool = True


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def infer_package(corpus: SkillCorpus, config: InferenceConfig) -> InferredPackage:
    """Run the full plan -> per-document pipeline. Returns a fully-validated InferredPackage."""
    api_key = config.api_key or os.environ.get("CLAUDE_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("No API key — set CLAUDE_API_KEY in .env or pass --api-key")

    client = anthropic.Anthropic(api_key=api_key).with_options(timeout=600.0)
    runner = _Runner(client, corpus, config)
    return runner.run()


# ---------------------------------------------------------------------------
# Runner — orchestrates the multi-call pipeline
# ---------------------------------------------------------------------------


class _Runner:
    def __init__(self, client: anthropic.Anthropic, corpus: SkillCorpus, config: InferenceConfig):
        self.client = client
        self.corpus = corpus
        self.config = config
        self.system_blocks = _build_system_prompt()
        self.skill_index = {s.name: s for s in corpus.skills}

    def run(self) -> InferredPackage:
        plan = self._infer_plan()
        self._log(f"  Plan: agent_id={plan.agent_id} skills={len(plan.skills)} "
                  f"tools={len(plan.tools)} guardrails={len(plan.guardrails)}")

        agent_registry = self._infer_agent_registry(plan)
        skills = [self._infer_skill(plan, sp) for sp in plan.skills]
        tools = [self._infer_tool(plan, tp) for tp in plan.tools]
        guardrails = [self._infer_guardrail(plan, gp) for gp in plan.guardrails]

        return InferredPackage(
            agent_registry=agent_registry,
            skills=skills,
            tools=tools,
            guardrails=guardrails,
        )

    # ------ per-call wrappers ------

    def _infer_plan(self) -> PackagePlan:
        self._log("  Step 1/4: planning…")
        user = self._render_corpus(
            "Inspect the skill(s) and produce a PackagePlan inventorying every "
            "skill, tool (one per executable script), and guardrail you intend to emit. "
            "Be exhaustive — every plausibly-callable script becomes a tool. "
            "Pure helpers/utilities can be skipped if they don't make sense as standalone tools.\n\n"
            f"Domain: {self.config.domain}"
        )
        return self._infer_strict(PackagePlan, user, label="plan")

    def _infer_agent_registry(self, plan: PackagePlan) -> AgentRegistry:
        self._log("  Step 2/4: agent_registry…")
        user = (
            f"Produce the AgentRegistry for this plan. agent_id MUST be {plan.agent_id!r}, "
            f"name MUST be {plan.name!r}, domain MUST be {plan.domain!r}. "
            f"skill_refs MUST list exactly: {[s.skill_id for s in plan.skills]}.\n\n"
            f"Plan:\n{plan.model_dump_json(indent=2)}\n\n"
            f"{self._render_corpus_brief()}"
        )
        return self._infer_strict(AgentRegistry, user, label="agent_registry")

    def _infer_skill(self, plan: PackagePlan, sp: SkillPlan) -> Skill:
        """Two strict calls: SkillBody (everything but execution_plan), then ExecutionPlan.

        The merged Skill schema is too complex for Anthropic's grammar compiler in one
        shot; this split keeps each individual grammar within bounds.
        """
        source = self.skill_index.get(sp.source_skill_name)
        if source is None:
            raise RuntimeError(f"plan references unknown source skill {sp.source_skill_name!r}")
        rendered = _render_source_skill(source)
        skill_constraints = (
            f"skill_id MUST be {sp.skill_id!r}, owner_agent_id MUST be {plan.agent_id!r}, "
            f"domain MUST be {plan.domain!r}, tool_ids MUST be exactly {sp.tool_ids!r}."
        )

        self._log(f"  Step 3/4: skill {sp.skill_id} (body)…")
        body_user = (
            f"Produce SkillBody (the Skill object MINUS the execution_plan field). "
            f"{skill_constraints}\n\nPlan:\n{plan.model_dump_json(indent=2)}\n\n"
            f"=== Source skill ===\n{rendered}"
        )
        body = self._infer_strict(SkillBody, body_user, label=f"skill:{sp.skill_id}:body")

        self._log(f"  Step 3/4: skill {sp.skill_id} (execution_plan)…")
        plan_user = (
            f"Produce the ExecutionPlan for skill {sp.skill_id!r}. The plan must orchestrate "
            f"calls to tool_ids {sp.tool_ids!r} so that this skill can fulfill its purpose. "
            f"Each step's tool_class must match the corresponding tool's tool_class.\n\n"
            f"Skill body so far:\n{body.model_dump_json(indent=2)}\n\n"
            f"=== Source skill ===\n{rendered}"
        )
        execution_plan = self._infer_strict(
            ExecutionPlan, plan_user, label=f"skill:{sp.skill_id}:plan"
        )
        return Skill(**body.model_dump(), execution_plan=execution_plan)

    def _infer_tool(self, plan: PackagePlan, tp: ToolPlan) -> InferredTool:
        self._log(f"  Step 3/4: tool {tp.tool_id}…")
        source = self.skill_index.get(tp.source_skill_name)
        if source is None:
            raise RuntimeError(f"plan references unknown source skill {tp.source_skill_name!r}")
        file_match = next((f for f in source.files if f.relpath == tp.source_filename), None)
        if file_match is None:
            raise RuntimeError(
                f"plan tool {tp.tool_id!r} references missing file {tp.source_filename!r} "
                f"in skill {tp.source_skill_name!r}. files: {[f.relpath for f in source.files]}"
            )
        user = (
            f"Produce the full Tool spec for `{tp.tool_id}`. "
            f"tool_id MUST be {tp.tool_id!r}. domain MUST include {plan.domain!r}. "
            f"source_code.filename MUST be {tp.tool_id + Path(tp.source_filename).suffix!r}.\n\n"
            f"Purpose hint from plan: {tp.one_line_purpose}\n\n"
            f"=== Source file ({tp.source_filename}, language inferred from extension) ===\n"
            f"{file_match.content}"
        )
        spec = self._infer_strict(Tool, user, label=f"tool:{tp.tool_id}")
        return InferredTool(
            spec=spec,
            source_skill_name=tp.source_skill_name,
            source_filename=tp.source_filename,
        )

    def _infer_guardrail(self, plan: PackagePlan, gp: GuardrailPlan) -> Guardrail:
        self._log(f"  Step 4/4: guardrail {gp.guardrail_id}…")
        user = (
            f"Produce the full Guardrail. guardrail_id MUST be {gp.guardrail_id!r}, "
            f"name MUST be {gp.name!r}, scope MUST be {gp.scope!r}, "
            f"domain MUST be {plan.domain!r}, "
            f"skill_id MUST be {gp.skill_id!r}.\n\n"
            f"Motivating concern: {gp.motivating_concern}\n\n"
            "Generate 2–5 enforceable rules expanding on the concern. "
            "Each rule needs a unique snake_case rule_id, a one-sentence description, "
            "an enforcement (hard/soft), and an action (block/warn/log).\n\n"
            f"{self._render_corpus_brief()}"
        )
        return self._infer_strict(Guardrail, user, label=f"guardrail:{gp.guardrail_id}")

    # ------ retry-aware strict caller ------

    def _infer_strict(self, schema: type[T], user_text: str, *, label: str) -> T:
        max_retries = max(1, self.config.max_retries)
        last_error: Exception | None = None
        feedback: Optional[str] = None
        for attempt in range(1, max_retries + 1):
            content = user_text if feedback is None else (
                f"{user_text}\n\n=== PREVIOUS ATTEMPT FAILED — DO NOT REPEAT ===\n{feedback}"
            )
            try:
                response = self.client.messages.parse(
                    model=MODEL,
                    max_tokens=8192,
                    thinking={"type": "adaptive"},
                    output_config={"effort": "high"},
                    system=self.system_blocks,
                    messages=[{"role": "user", "content": content}],
                    output_format=schema,
                )
                if response.stop_reason == "refusal":
                    raise RuntimeError(f"refusal: {getattr(response, 'stop_details', None)}")
                if response.parsed_output is None:
                    raise RuntimeError(f"no parsed_output (stop_reason={response.stop_reason})")
                self._log_usage(label, response.usage)
                return response.parsed_output
            except (ValidationError, RuntimeError) as e:
                last_error = e
                feedback = str(e)
                self._log(f"    {label} attempt {attempt}/{max_retries} failed: "
                          f"{type(e).__name__}: {str(e)[:200]}")
            except anthropic.BadRequestError as e:
                msg = str(e)
                if "compiled grammar is too large" in msg:
                    raise RuntimeError(
                        f"{label}: schema too large for strict mode. "
                        f"Split this document type further."
                    ) from e
                last_error = e
                feedback = msg
                self._log(f"    {label} attempt {attempt}/{max_retries} bad request: {msg[:200]}")
        raise RuntimeError(f"{label}: exhausted {max_retries} retries. Last error: {last_error}")

    # ------ helpers ------

    def _log(self, msg: str) -> None:
        if self.config.verbose:
            print(msg)

    def _log_usage(self, label: str, usage) -> None:
        if not self.config.verbose:
            return
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
        cache_write = getattr(usage, "cache_creation_input_tokens", 0) or 0
        self._log(f"    {label}: in={usage.input_tokens} out={usage.output_tokens} "
                  f"cache_read={cache_read} cache_write={cache_write}")

    def _render_corpus(self, instruction: str) -> str:
        chunks = [instruction, "", f"Source: {self.corpus.source}"]
        for s in self.corpus.skills:
            chunks.append(_render_source_skill(s))
        return "\n".join(chunks)

    def _render_corpus_brief(self) -> str:
        chunks = ["=== Skill summaries ==="]
        for s in self.corpus.skills:
            desc = (s.frontmatter.get("description") or "").strip()
            chunks.append(f"- {s.name}: {desc[:300]}")
        return "\n".join(chunks)


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


def _build_system_prompt() -> list[dict]:
    """Frozen system prompt: rules + spec + reference packages, marked cacheable."""
    spec = SPEC_PATH.read_text(encoding="utf-8")
    references = _load_reference_packages()

    rules = (
        "You are an Escher ADK package authoring agent. You convert agentskills.io / "
        "Anthropic SKILL.md skills into a strict ADK package — one document at a time.\n\n"
        "Identifier rules:\n"
        "- agent_id = `domain.{domain}.{name}` (e.g. `domain.security.exposure`).\n"
        "- skill_id = `{domain}.{snake_case_action}` (e.g. `security.detect_public_ingress`).\n"
        "- tool_id is conventionally `{provider}.{snake_verb_object}` (e.g. `aws.query_cost_explorer`).\n"
        "- guardrail_id = `{domain}.{snake_case_concern}`.\n"
        "- All identifiers are lowercase snake_case with optional dot separators. No hyphens, no spaces.\n\n"
        "Cross-reference rules:\n"
        "- agent_registry.skill_refs[] must list every skill_id you emit.\n"
        "- skill.tool_ids[] must reference only tool_ids you also emit.\n"
        "- skill.owner_agent_id must equal the agent_id.\n"
        "- tool source_code.filename must equal `{tool_id}.{ext}` where ext matches the source language.\n"
        "- All documents: tenant_id is null, version is `0.1.0` unless the skill frontmatter specifies otherwise.\n\n"
        "Use the spec and reference packages below as the authoritative format. Do not invent fields. "
        "Do not omit required fields. When asked for a single document, emit only that document, "
        "respecting any constraint hints in the user message."
    )
    return [
        {"type": "text", "text": rules},
        {"type": "text", "text": "\n\n=== package_format.md (spec) ===\n\n" + spec},
        {
            "type": "text",
            "text": "\n\n=== Reference packages (existing escher-adk-packages) ===\n\n" + references,
            "cache_control": {"type": "ephemeral"},
        },
    ]


def _load_reference_packages() -> str:
    if not REFERENCE_DIR.exists():
        return "(no reference packages available)"
    chunks: list[str] = []
    for path in sorted(REFERENCE_DIR.rglob("*.json")):
        rel = path.relative_to(REFERENCE_DIR.parent).as_posix()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        chunks.append(f"# {rel}\n{json.dumps(data, indent=2, sort_keys=True)}")
    return "\n\n".join(chunks)


def _render_source_skill(skill: SourceSkill) -> str:
    parts = [
        f"=== Skill: {skill.name} ===",
        f"Frontmatter: {json.dumps(skill.frontmatter, sort_keys=True)}",
        "",
        "SKILL.md body:",
        skill.body,
        "",
        "Files in skill directory:",
    ]
    for f in skill.files:
        marker = "EXECUTABLE" if f.is_executable else "DOC"
        parts.append(f"\n--- [{marker}] {f.relpath} ---\n{f.content}")
    return "\n".join(parts)
