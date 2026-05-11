# Escher Agent Package Format

## Overview

The agent package is the canonical unit of authoring and registration in the Escher platform. It is the **single interface** between:

- **Authoring Agent** — generates the package through conversational interview + Code Agent
- **ADK CLI** — `adk register ./package` submits it to CE
- **CE CRUD API** — `/register/agent-package` consumes it and places each document into the correct collection

Every JSON document in the package maps 1:1 to a CE collection schema defined in `schema_json.md`. There is no intermediate YAML format, no translation layer.

---

## Folder Structure

```
package/
  agent_registry.json              → escher_agent_registry_global     (§2.11)

  skills/
    {skill_id}.json                → escher_skills_global              (§2.2)
                                     JSON only — skills are declarative spec, no code

  tools/
    {tool_id}/                     → one subdirectory per tool
      {tool_id}.json               → escher_tools_global               (§2.4)
      {tool_id}.{ext}              → S3 — main tool executable (new tools only)
      {helper}.{ext}               → S3 — optional additional files (helpers, utils, etc.)
      requirements.txt             → S3 — optional dependencies
                                     language determined by source_code.language in tool JSON

  guardrails/
    {guardrail_id}.json            → escher_guardrails_global          (§2.5)

  templates/
    {template_id}.json             → escher_templates_global           (§2.7)

  domain_lens/
    {lens_id}.json                 → escher_domain_lens_global         (§2.6)
                                     content_type: "framework" | "policy" | "standard" | "cloud_service"
                                     cloud_service = merged §2.9 (Cloud Knowledge) — same folder, same schema

  playbooks/                       ⚠ FUTURE — write operations (Stage 5W not yet designed)
    {playbook_id}.json             → escher_playbooks_global           (§2.8)
    {playbook_id}.py               → S3 — playbook scripts

  expert_graph/                    ⚠ FUTURE — advanced tier, platform-curated only
    nodes.json                     → escher_domain_expert_graph        (§2.12)
    edges.json
```

### Rules

- `agent_registry.json` is mandatory — registration fails without it
- Every `skill_id` in `agent_registry.skill_refs[]` must have a matching `skills/{skill_id}.json`
- Every `tool_id` in `skills/{skill_id}.tool_ids[]` must have a matching `tools/{tool_id}.json` **or** already exist in CE
- Skills have no executable — `skills/` contains JSON documents only
- `tools/{tool_id}.{ext}` is required only for new tools — existing CE tools have no source file in the package
- Tool executable language is declared in `source_code.language` inside the tool JSON
- `domain_lens/*.json` contains source references only — no inline content (CE fetches and indexes at registration)
- Cloud service knowledge docs (`content_type: "cloud_service"`) go in `domain_lens/` — there is no separate `cloud_knowledge/` folder; the §2.6 schema covers both domain philosophy docs and cloud service reference docs via `content_type`
- Registration is atomic — if any document fails validation, nothing is placed

---

## S3 Storage

Tool executables and playbook scripts are not stored in CE — they are stored in S3 and fetched by the gateway or client on demand.

### Buckets

| Bucket | Purpose | Key Pattern |
|---|---|---|
| `escher-adk-packages` | Full ADK packages — uploaded by `adk register`. Contains the complete package folder per registration. | `{package_name}/tools/{tool_id}/{tool_id}.{ext}` |
| `escher-adk-tools` | Tool scripts only — individual executables served by the gateway to the client. Canonical runtime store. | `{tool_id}/{version}/{tool_id}.{ext}` |

### `escher-adk-tools` — Key Structure

This is the bucket the gateway reads from when a client requests a tool script via `GET /api/v4/tools/script`.

```
{tool_id}/
  {version}/
    {tool_id}.{ext}           ← main executable (e.g. aws.query_cost_explorer.py)
    {helper}.{ext}            ← optional helpers / utils
    requirements.txt          ← optional dependencies
```

Example:
```
aws.query_cost_explorer/
  0.1.0/
    aws.query_cost_explorer.py
```

Full URL: `https://escher-adk-tools.s3.us-east-1.amazonaws.com/{tool_id}/{version}/{tool_id}.{ext}`

### `escher-adk-packages` — Key Structure

Used by the ADK CLI during `adk register`. Contains the full package as submitted, preserving the folder layout defined above.

```
{package_name}/
  tools/
    {tool_id}/
      {tool_id}.json
      {tool_id}.{ext}
```

Example: `https://escher-adk-packages.s3.us-east-1.amazonaws.com/cost-package/tools/aws.query_cost_explorer/aws.query_cost_explorer.py`

### Access

- `escher-adk-tools` — gateway ECS task role has `s3:GetObject` on `escher-adk-tools/*`. Scripts are fetched by the gateway at `GET /api/v4/tools/script?tool_id=&version=&language=` and streamed to the client.
- `escher-adk-packages` — write access granted to the ADK CLI role only. Read access for internal tooling.

---

## Sample Package — `domain.security.exposure`

A complete, registration-ready package for the security exposure agent.

---

### `agent_registry.json`

```json
{
  "agent_id":     "domain.security.exposure",
  "name":         "exposure",
  "display_name": "Security Exposure Agent",
  "agent_type":   "domain",
  "domain":       "security",
  "tier_support": ["basic", "advanced"],
  "status":       "active",
  "tenant_id":    null,

  "purpose": "Detect publicly exposed cloud resources and rank findings by severity.",
  "description": "Detects public ingress risks, open S3 buckets, and internet-facing resources. Ranks and prioritises exposure findings. Use for questions like: which EC2s are exposed, what security groups are open, show me public-facing resources in my AWS account.",

  "capabilities": [
    "detect public ingress and network exposure risks",
    "detect public storage access and open S3 buckets",
    "rank and prioritize exposure findings by severity",
    "suggest basic remediation paths for exposure risks"
  ],

  "supported_context_types": [
    "public_exposure_inventory",
    "resource_scope_summary",
    "environment_scope"
  ],

  "skill_refs": [
    "security.detect_public_ingress",
    "security.detect_public_storage_access"
  ],

  "composition": {
    "usable_in_profiles":    ["hero_admin", "cspm_deep"],
    "compatible_agents":     ["domain.security.remediation_planning"],
    "conflicts_with_agents": []
  },

  "owner": {
    "team":    "platform-security",
    "contact": "security-team@escher.ai"
  },

  "version":   "0.1.0"
}
```

---

### `skills/security.detect_public_ingress.json`

```json
{
  "skill_id":       "security.detect_public_ingress",
  "display_name":   "Detect Public Ingress",
  "owner_agent_id": "domain.security.exposure",
  "capability_id":  "detect_public_exposure",
  "domain":         "security",
  "tier":           "basic",
  "status":         "active",
  "tenant_id":      null,

  "purpose":     "Detect public ingress patterns and generate exposure findings.",
  "description": "Finds publicly accessible EC2 instances, open security groups, internet-facing load balancers, and public S3 buckets. Use this for questions like: which EC2 instances are unsecured, what security groups have open ingress, show me public-facing resources, find exposed infrastructure in my AWS account.",

  "capabilities": [
    "detect publicly accessible EC2 instances with open ingress rules",
    "find security groups allowing 0.0.0.0/0 on sensitive ports",
    "identify internet-facing load balancers with no WAF",
    "surface network exposure findings with severity ranking"
  ],

  "context_descriptions": [
    "security group ingress rules — open ports, CIDR ranges, protocol configurations",
    "internet gateway associations — VPCs with public internet connectivity",
    "load balancer listeners — public-facing ALB and NLB configurations"
  ],

  "supported_context_types": [
    "public_exposure_inventory",
    "resource_scope_summary",
    "environment_scope"
  ],

  "tool_affinity": {
    "allowed_tool_classes": ["inventory_read"],
    "preferred_tool_tags":  ["security", "ingress", "aws"],
    "execution_locations":  ["client"]
  },

  "context": {
    "merge_strategy":      "union",
    "dedupe_keys":         ["environment"],
    "max_parallel":        3,
    "on_missing_required": "request_more"
  },

  "execution_plan": {
    "steps": [
      {
        "step_id":                  "fetch_exposure_inventory",
        "context_type":             "public_exposure_inventory",
        "tool_class":               "inventory_read",
        "preferred_tool_tags":      ["security", "ingress", "aws"],
        "depends_on":               [],
        "required":                 true,
        "on_failure":               "stop",
        "freshness_window":         "30m",
        "cache_policy":             "refresh_if_stale",
        "normalization_schema_ref": "schemas/public_exposure_inventory.yaml"
      },
      {
        "step_id":                  "fetch_resource_scope",
        "context_type":             "resource_scope_summary",
        "tool_class":               "inventory_read",
        "preferred_tool_tags":      ["security", "storage", "aws"],
        "depends_on":               ["fetch_exposure_inventory"],
        "required":                 false,
        "on_failure":               "skip",
        "freshness_window":         "30m",
        "cache_policy":             "refresh_if_stale",
        "normalization_schema_ref": "schemas/storage_exposure_inventory.yaml"
      },
      {
        "step_id":      "fetch_environment_scope",
        "context_type": "environment_scope",
        "tool_class":   "inventory_read",
        "depends_on":   [],
        "required":     false,
        "on_failure":   "skip"
      }
    ],
    "on_partial_failure": "continue"
  },

  "output_type":       "finding",
  "output_schema_ref": "schemas/public_exposure_finding.yaml",

  "client_action_type": "estate-scanner",

  "tool_ids": [
    "aws.describe_public_ingress_surface"
  ],

  "artifact_effects": {
    "can_create": ["finding"],
    "can_update": [],
    "can_enrich": ["triage"]
  },

  "action_semantics": {
    "can_request_execution":            false,
    "can_generate_plan_fragments":      true,
    "can_generate_bundle_hints":        false,
    "can_generate_playbook_candidates": true
  },

  "safety": {
    "safety_class":              "advisory",
    "requires_human_review_for": []
  },

  "evidence": {
    "emits_rationale":  true,
    "emits_confidence": true
  },

  "version": "0.1.0"
}
```

---

### `tools/aws.describe_public_ingress_surface.json`

```json
{
  "tool_id":     "aws.describe_public_ingress_surface",
  "name":        "Describe Public Ingress Surface",
  "description": "Fetch security group ingress rules and internet-facing resources.",
  "tool_class":  "inventory_read",
  "tool_type":   "readonly",

  "domain":         ["security"],
  "provider":       "aws",
  "resource_types": ["security_group", "load_balancer", "internet_gateway"],
  "api_calls": [
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeInternetGateways",
    "elasticloadbalancing:DescribeLoadBalancers"
  ],

  "source_code": {
    "filename":   "aws.describe_public_ingress_surface.py",
    "language":   "python"
  },

  "execution_location": "client",
  "execution_timeout":  30,

  "input_schema": {
    "parameters": [
      {
        "name":        "region",
        "type":        "string",
        "required":    true,
        "description": "AWS region to scan (e.g. us-east-1)"
      },
      {
        "name":        "vpc_ids",
        "type":        "list",
        "required":    false,
        "description": "Restrict scan to specific VPC IDs — null means all VPCs"
      }
    ]
  },

  "output_schema_ref": "schemas/public_exposure_inventory.yaml",
  "safety_class":      "read_only",
  "cacheable":         true,
  "version":           "0.1.0",
  "tenant_id":         null
}
```

---

### `tools/aws.describe_public_ingress_surface.py`

```python
import boto3

def run(params: dict) -> dict:
    """
    Tool implementation — fetches security groups and internet gateways.
    Returns normalized public_exposure_inventory.
    """
    session = boto3.Session(
        profile_name=params.get("profile"),
        region_name=params["region"]
    )
    ec2 = session.client("ec2")

    sg_response  = ec2.describe_security_groups()
    igw_response = ec2.describe_internet_gateways()

    security_groups = []
    for sg in sg_response.get("SecurityGroups", []):
        ingress_rules = [
            {
                "port":     perm.get("FromPort", -1),
                "protocol": perm.get("IpProtocol", "all"),
                "cidr":     r["CidrIp"]
            }
            for perm in sg.get("IpPermissions", [])
            for r in perm.get("IpRanges", [])
        ]
        if ingress_rules:
            security_groups.append({
                "group_id":     sg["GroupId"],
                "group_name":   sg["GroupName"],
                "vpc_id":       sg.get("VpcId"),
                "ingress_rules": ingress_rules
            })

    return {
        "security_groups":      security_groups,
        "internet_gateway_ids": [
            igw["InternetGatewayId"]
            for igw in igw_response.get("InternetGateways", [])
        ]
    }
```

---

### `guardrails/security.never_fabricate_findings.json`

```json
{
  "guardrail_id":   "security.never_fabricate_findings",
  "name":           "Never fabricate security findings",
  "scope":          "domain",
  "skill_id":       null,
  "owner_agent_id": null,
  "domain":         "security",
  "tenant_id":      null,

  "rules": [
    {
      "rule_id":     "no_invented_findings",
      "description": "Never report a security finding without direct evidence from estate data.",
      "enforcement": "hard",
      "action":      "block"
    },
    {
      "rule_id":     "cite_evidence_source",
      "description": "Every finding must reference the specific resource and tool output.",
      "enforcement": "hard",
      "action":      "block"
    },
    {
      "rule_id":     "confidence_required",
      "description": "Every finding must include a confidence score.",
      "enforcement": "soft",
      "action":      "warn"
    }
  ],

  "version": "0.1.0"
}
```

---

### `templates/security.exposure_finding_template.json`


```markdown
# SOC2 Compliance Report

## About
Provides a SOC2 compliance assessment of the user's cloud account.
Covers all five Trust Service Criteria: Security, Availability,
Processing Integrity, Confidentiality, and Privacy. Surfaces
compliance score, control-level findings, gaps, and remediation plans.

## Does Not Handle
Does not handle general security queries unrelated to SOC2.
Does not handle cost, billing, or resource configuration queries.
Does not modify compliance settings or create compliance policies.

## When To Use
Keywords: soc2, soc 2, compliance, trust criteria, audit, compliant,
          controls, findings, gaps, evidence, audit ready, type ii,
          aicpa, ccm, trust services
Use when: User is asking about SOC2 compliance status, gaps,
          control failures, or audit readiness

## Example Questions
- "Is my AWS account SOC2 compliant?"
- "Show me my SOC2 compliance gaps"
- "What controls are failing for SOC2?"
- "Am I ready for a SOC2 audit?"
- "What's my SOC2 score?"
- "Which SOC2 controls need attention?"
- "Show me evidence for SOC2 controls"

## Personas

### CEO
Focus: Overall compliance posture, key risks, top 3 actions

Chat: alert, summary, score, metrics, recommendations
Canvas: breakdown, detail_table

### Auditor
Focus: Full control-level evidence, all findings, complete report

Chat: alert, summary, score, findings, recommendations
Canvas: status_table, detail_table, analysis, plan

### DevOps
Focus: Specific failing controls, technical remediation detail

Chat: alert, summary, findings, recommendations, actions
Canvas: status_table, detail_table, code, plan, bundle

### Security
Focus: Control failures, risk exposure, remediation steps

Chat: alert, summary, score, findings, recommendations
Canvas: status_table, detail_table, plan, bundle

### Default
Use: Auditor

## Notes
Covers SOC2 Type II by default. For Type I queries the same
template applies — findings should focus on control design
rather than operating effectiveness.
Evidence links and audit log references are surfaced through
the findings block artifact slots.
```

---

### `domain_lens/security.cspm_framework_reference.json`

```json
{
  "lens_id":      "security.cspm_framework_reference",
  "domain":       "security",
  "title":        "CSPM Framework Reference",
  "content_type": "framework",
  "tenant_id":    null,

  "source": {
    "type":         "confluence",
    "ref":          "https://confluence.internal/display/SEC/CSPM+Framework",
    "fetched_at":   "2026-05-04T10:00:00Z",
    "content_hash": "sha256:3d4f9a1b2c8e7f6a"
  },

  "version": "0.1.0"
}
```

---

### `domain_lens/security.aws_security_hub_concepts.json`

Cloud service knowledge — `content_type: "cloud_service"`. Same schema as the framework reference above; `content_type` is the only differentiator.

```json
{
  "lens_id":      "security.aws_security_hub_concepts",
  "domain":       "security",
  "title":        "AWS Security Hub — Concepts and Finding Format",
  "content_type": "cloud_service",
  "tenant_id":    null,

  "source": {
    "type":         "url",
    "ref":          "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-concepts.html",
    "fetched_at":   "2026-05-04T10:00:00Z",
    "content_hash": "sha256:9b1e4c3d7f2a05b8"
  },

  "version": "0.1.0"
}
```

---

## Future Sections

### `playbooks/` ⚠ NOT YET DESIGNED

Write operations authoring (Stage 5W) is deferred. When designed, playbook packages will follow this pattern:

```
playbooks/
  {playbook_id}.json     ← §2.8 schema — operation definition, steps, parameters
  {playbook_id}.py       ← step scripts embedded in document.scripts[] + S3
```

Placeholder fields to define: operation type, confirmation requirements, rollback scripts, write tool selection.

### `expert_graph/` ⚠ FUTURE — PLATFORM-CURATED ONLY

Domain Expert Graph (§2.12) is not authored through the chat-based interview or ADK CLI. It is curated directly by platform and domain teams over time. When this authoring path is designed, the package will include:

```
expert_graph/
  nodes.json     ← Control, Requirement, EvidenceType, ResourceType, Risk, Remediation nodes
  edges.json     ← requires, evidenced_by, collected_via, is_a, remediated_by edges
```

Advanced tier packages only. Referential integrity validated at registration.

### `integrations/` ⚠ FUTURE

Integration agent packages (Slack, Jira, Linear, GitHub) will follow the same format with an additional `integrations/` folder for connector definitions.

---

## Schema Source of Truth

Every JSON document in this package must conform to the schemas defined in `schema_json.md`:

| Folder | File | Schema Section |
|---|---|---|
| root | `agent_registry.json` | §2.11 Agent Registry |
| `skills/` | `{skill_id}.json` | §2.2 Skill Collection — JSON only, no executable |
| `tools/` | `{tool_id}.json` | §2.4 Tool Collection |
| `tools/` | `{tool_id}.{ext}` | S3 — source declared in `source_code.language` |
| `guardrails/` | `{guardrail_id}.json` | §2.5 Guardrail Collection |
| `templates/` | `{template_id}.json` | §2.7 Template Collection |
| `domain_lens/` | `{lens_id}.json` | §2.6 Domain Lens Collection (`content_type: "cloud_service"` covers merged §2.9) |
| `playbooks/` | `{playbook_id}.json` | §2.8 Playbook Collection _(future)_ |
| `expert_graph/` | `nodes.json`, `edges.json` | §2.12 Domain Expert Graph _(future)_ |

Any change to a collection schema in `schema_json.md` automatically affects what the Authoring Agent generates, what the ADK CLI validates, and what the CE CRUD API accepts.
