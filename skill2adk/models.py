"""Pydantic models for the Escher ADK package format.

Source of truth: spec/package_format.md (§ Sample Package). Model is also validated
against every JSON file under escher-adk-packages/ — see tests/validate_reference.py.

All models use extra="forbid" to catch unknown fields early at registration time.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Shared primitives
# ---------------------------------------------------------------------------

_Strict = ConfigDict(extra="forbid")

Tier = Literal["basic", "advanced"]
Status = Literal["active", "inactive", "deprecated"]
Enforcement = Literal["hard", "soft"]
RuleAction = Literal["block", "warn", "log"]
ExecutionLocation = Literal["client", "server"]


# ---------------------------------------------------------------------------
# Agent Registry — package/agent_registry.json
# ---------------------------------------------------------------------------


class Owner(BaseModel):
    model_config = _Strict
    team: str
    contact: str


class Composition(BaseModel):
    model_config = _Strict
    usable_in_profiles: list[str] = Field(default_factory=list)
    compatible_agents: list[str] = Field(default_factory=list)
    conflicts_with_agents: list[str] = Field(default_factory=list)


class AgentRegistry(BaseModel):
    model_config = _Strict
    agent_id: str
    name: str
    display_name: str
    agent_type: Literal["domain"]
    domain: str
    tier_support: list[Tier]
    status: Status
    tenant_id: Optional[str] = None
    purpose: str
    description: str
    capabilities: list[str]
    supported_context_types: list[str]
    skill_refs: list[str]
    composition: Composition
    owner: Owner
    version: str


# ---------------------------------------------------------------------------
# Skill — package/skills/{skill_id}.json
# ---------------------------------------------------------------------------


class ToolAffinity(BaseModel):
    model_config = _Strict
    allowed_tool_classes: list[str]
    preferred_tool_tags: list[str] = Field(default_factory=list)
    execution_locations: list[ExecutionLocation]


class ContextPolicy(BaseModel):
    model_config = _Strict
    merge_strategy: Literal["union", "replace", "append"]
    dedupe_keys: list[str] = Field(default_factory=list)
    max_parallel: int
    on_missing_required: Literal["request_more", "fail", "skip"]


class ExecutionStep(BaseModel):
    model_config = _Strict
    step_id: str
    context_type: str
    tool_class: str
    preferred_tool_tags: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    required: bool
    on_failure: Literal["stop", "skip", "continue"]
    freshness_window: Optional[str] = None
    cache_policy: Optional[Literal["refresh_if_stale", "always_fresh", "never_refresh"]] = None
    normalization_schema_ref: Optional[str] = None


class ExecutionPlan(BaseModel):
    model_config = _Strict
    steps: list[ExecutionStep]
    on_partial_failure: Literal["fail", "continue"]


class ArtifactEffects(BaseModel):
    model_config = _Strict
    can_create: list[str] = Field(default_factory=list)
    can_update: list[str] = Field(default_factory=list)
    can_enrich: list[str] = Field(default_factory=list)


class ActionSemantics(BaseModel):
    model_config = _Strict
    can_request_execution: bool
    can_generate_plan_fragments: bool
    can_generate_bundle_hints: bool
    can_generate_playbook_candidates: bool


class Safety(BaseModel):
    model_config = _Strict
    safety_class: Literal["advisory", "destructive", "restricted"]
    requires_human_review_for: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    model_config = _Strict
    emits_rationale: bool
    emits_confidence: bool


class Skill(BaseModel):
    model_config = _Strict
    skill_id: str
    display_name: str
    owner_agent_id: str
    capability_id: str
    domain: str
    tier: Tier
    status: Status
    tenant_id: Optional[str] = None
    purpose: str
    description: str
    capabilities: list[str]
    context_descriptions: list[str]
    supported_context_types: list[str]
    tool_affinity: ToolAffinity
    context: ContextPolicy
    execution_plan: ExecutionPlan
    output_type: str
    output_schema_ref: str
    client_action_type: str
    tool_ids: list[str]
    artifact_effects: ArtifactEffects
    action_semantics: ActionSemantics
    safety: Safety
    evidence: Evidence
    version: str


class SkillBody(BaseModel):
    """Skill minus execution_plan — used to keep the strict-mode grammar compact."""

    model_config = _Strict
    skill_id: str
    display_name: str
    owner_agent_id: str
    capability_id: str
    domain: str
    tier: Tier
    status: Status
    tenant_id: Optional[str] = None
    purpose: str
    description: str
    capabilities: list[str]
    context_descriptions: list[str]
    supported_context_types: list[str]
    tool_affinity: ToolAffinity
    context: ContextPolicy
    output_type: str
    output_schema_ref: str
    client_action_type: str
    tool_ids: list[str]
    artifact_effects: ArtifactEffects
    action_semantics: ActionSemantics
    safety: Safety
    evidence: Evidence
    version: str


# ---------------------------------------------------------------------------
# Tool — package/tools/{tool_id}/{tool_id}.json
# ---------------------------------------------------------------------------


class ToolParameter(BaseModel):
    model_config = _Strict
    name: str
    type: Literal["string", "integer", "number", "boolean", "list", "object"]
    required: bool
    description: str


class ToolInputSchema(BaseModel):
    model_config = _Strict
    parameters: list[ToolParameter]


class ToolSourceCode(BaseModel):
    model_config = _Strict
    filename: str
    language: Literal["python", "javascript", "typescript", "go", "bash"]
    git_loc: Optional[str] = None
    git_tag: Optional[str] = None


class Tool(BaseModel):
    model_config = _Strict
    tool_id: str
    name: str
    description: str
    tool_class: str
    tool_type: Literal["readonly", "write", "mutating"]
    domain: list[str]
    provider: Literal["aws", "azure", "gcp", "kubernetes", "generic"]
    resource_types: list[str]
    api_calls: list[str]
    source_code: ToolSourceCode
    execution_location: ExecutionLocation
    execution_timeout: int
    input_schema: ToolInputSchema
    output_schema_ref: str
    safety_class: Literal["read_only", "destructive", "restricted"]
    cacheable: bool
    version: str
    tenant_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Guardrail — package/guardrails/{guardrail_id}.json
# ---------------------------------------------------------------------------


class GuardrailRule(BaseModel):
    model_config = _Strict
    rule_id: str
    description: str
    enforcement: Enforcement
    action: RuleAction


class Guardrail(BaseModel):
    model_config = _Strict
    guardrail_id: str
    name: str
    scope: Literal["domain", "skill", "agent"]
    skill_id: Optional[str] = None
    owner_agent_id: Optional[str] = None
    domain: str
    tenant_id: Optional[str] = None
    rules: list[GuardrailRule]
    version: str


# ---------------------------------------------------------------------------
# Tool source file — bundled with the JSON
# ---------------------------------------------------------------------------


class ToolFile(BaseModel):
    """A source file that should be written next to a tool's JSON."""

    model_config = _Strict
    filename: str
    content: str


class ToolBundle(BaseModel):
    """A tool plus its source code file(s)."""

    model_config = _Strict
    spec: Tool
    files: list[ToolFile]


# ---------------------------------------------------------------------------
# Top-level package — what the converter emits
# ---------------------------------------------------------------------------


class AdkPackage(BaseModel):
    model_config = _Strict
    agent_registry: AgentRegistry
    skills: list[Skill]
    tools: list[ToolBundle]
    guardrails: list[Guardrail]


# ---------------------------------------------------------------------------
# Inference output — what the LLM returns. The .py source is NOT in this shape;
# the writer copies it from the SkillCorpus using `source_filename` to find it.
# ---------------------------------------------------------------------------


class InferredTool(BaseModel):
    model_config = _Strict
    spec: Tool
    source_filename: str = Field(
        description="Relative path of the source file inside the originating skill directory "
                    "(e.g. 'scripts/check_bounding_boxes.py'). The writer copies this file "
                    "to tools/{tool_id}/{tool_id}.{ext}.",
    )
    source_skill_name: str = Field(
        description="The 'name' field from the originating skill's frontmatter — used to look "
                    "up the source file in the corpus.",
    )


class InferredPackage(BaseModel):
    """The LLM's inference output. The writer turns this + the SkillCorpus into an AdkPackage."""

    model_config = _Strict
    agent_registry: AgentRegistry
    skills: list[Skill]
    tools: list[InferredTool]
    guardrails: list[Guardrail]


# ---------------------------------------------------------------------------
# Plan — a tiny strict-friendly schema returned by the first inference call.
# Per-document calls then expand each entry into a full AgentRegistry / Skill /
# Tool / Guardrail. Splitting this way keeps every individual grammar small.
# ---------------------------------------------------------------------------


class ToolPlan(BaseModel):
    model_config = _Strict
    tool_id: str = Field(description="snake_case, dotted (e.g. aws.query_cost_explorer)")
    source_skill_name: str = Field(
        description="The originating skill's frontmatter `name` — used to find the file.",
    )
    source_filename: str = Field(
        description="Path of the source file inside the skill dir (e.g. 'scripts/foo.py').",
    )
    one_line_purpose: str = Field(
        description="One-sentence purpose — used to expand into the full Tool spec.",
    )


class SkillPlan(BaseModel):
    model_config = _Strict
    skill_id: str = Field(description="snake_case, dotted, prefixed with the domain")
    source_skill_name: str = Field(
        description="The originating skill's frontmatter `name`.",
    )
    tool_ids: list[str] = Field(description="tool_ids this skill executes")


class GuardrailPlan(BaseModel):
    model_config = _Strict
    guardrail_id: str = Field(description="snake_case, dotted, prefixed with the domain")
    name: str
    scope: Literal["domain", "skill", "agent"]
    skill_id: Optional[str] = None
    motivating_concern: str = Field(
        description="One-sentence summary of why this guardrail exists; expanded into full rules later.",
    )


class PackagePlan(BaseModel):
    """Lightweight inventory of the package contents. One strict call produces this."""

    model_config = _Strict
    agent_id: str = Field(description="domain.{domain}.{name} — must match exactly")
    name: str = Field(description="short agent name (one word, snake_case)")
    display_name: str
    domain: str
    skills: list[SkillPlan]
    tools: list[ToolPlan]
    guardrails: list[GuardrailPlan]
