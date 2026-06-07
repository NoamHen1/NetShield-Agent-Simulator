#!/usr/bin/env python3
"""
NetShield AI Orchestrator (Step 5B).

Multi-agent pipeline that consumes logs/anomaly_snapshot.json and runs:

  1. Analyzer Agent  — free-text root-cause reasoning (Gemini, prose).
                       Its consumer is another LLM, so prose is fine.
  2. Strategist Agent — strict JSON mitigation plan (Gemini, structured output).
                       Its consumer will be the C++ enforcement plane, so the
                       schema is enforced at the inference layer — guaranteed
                       parseable, guaranteed-typed fields. No defensive parsing
                       needed downstream.

Outputs are printed to stdout. Step 5C will wire the Strategist's JSON into
the actual C++ enforcement mechanism.

Usage:
    GEMINI_API_KEY=... python3 scripts/ai_orchestrator.py
    GEMINI_API_KEY=... python3 scripts/ai_orchestrator.py --snapshot path/to/snap.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Literal

from google import genai
from google.genai import errors as genai_errors
from google.genai import types
from pydantic import BaseModel, Field

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
DEFAULT_SNAPSHOT: Path = REPO_ROOT / "logs" / "anomaly_snapshot.json"
DEFAULT_MODEL: str = "gemini-2.5-flash-lite"
FALLBACK_MODEL: str = "gemini-2.5-flash-lite"

# Delay inserted between the Analyzer and Strategist API calls. Both run
# back-to-back in microseconds; the free-tier token-bucket on Google AI Studio
# treats that as a burst and immediately fires 429 RESOURCE_EXHAUSTED. A small
# jitter spreads the two calls across separate bucket windows and reliably
# clears the limit. Tunable via env var for paid-tier deployments where the
# throttle is unnecessary overhead.
BURST_DELAY_SECONDS: float = float(os.environ.get("NETSHIELD_BURST_DELAY", "3.0"))


class MitigationStrategy(BaseModel):
    """Strict mitigation contract emitted by the Strategist agent.

    The Gemini API's structured-output mode constrains decoding so the
    response is guaranteed to parse into exactly this shape. Field types
    are enforced at the inference layer — the downstream C++ enforcer can
    trust block_source_id is an integer, not a string like "node 1".
    """

    action: Literal["BLOCK"] = Field(
        description="Mitigation verb. Only BLOCK is supported in this step."
    )
    apply_to_core_nodes: list[int] = Field(
        description="Core node IDs that should enforce the rule (drop matching ingress)."
    )
    block_source_id: int = Field(
        description="Logical node ID of the attacker. Traffic with this source_node_id is dropped."
    )


ANALYZER_SYSTEM_PROMPT = """\
You are a senior Network Security Expert reviewing a live telemetry snapshot
from a distributed UDP mesh that just tripped a DDoS anomaly threshold.

Your investigation method:
  1. Identify the SOURCE node of the attack. A flood source has an abnormally
     high `forwarded` counter (it is pumping packets out) but typically a low
     `queue_size` of its own. Cross-check by considering which node, given the
     topology edges, is the upstream of the congested path.
  2. Identify the CONGESTED CORE nodes — those whose `forwarded` counter is
     also abnormally high (they are relaying the flood) OR whose `queue_size`
     is saturated (they are buffering it).
  3. Identify the TARGET — typically the node whose `queue_size` actually
     tripped the trigger and whose `delivered` counter is climbing.

Output: concise technical prose, no markdown headings, no bullet lists.
Cite specific metric values (e.g. "node 1 forwarded=106,748"). Be decisive."""


STRATEGIST_SYSTEM_PROMPT = """\
You are the Mitigation Strategist. You receive the Analyzer's diagnosis plus
the original telemetry snapshot, and produce a mitigation plan.

Rules:
  - `action` is always "BLOCK" for now.
  - `block_source_id` must be the attacker node ID identified by the Analyzer.
  - `apply_to_core_nodes` must contain the core node IDs (role == "core" in
    topology) that sit on the attack path and should locally drop matching
    packets. Edge nodes are NEVER included here — only core nodes enforce.

Output JSON only, matching the provided schema."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the NetShield AI multi-agent mitigation pipeline."
    )
    parser.add_argument(
        "--snapshot",
        type=Path,
        default=DEFAULT_SNAPSHOT,
        help="Path to anomaly_snapshot.json (default: logs/anomaly_snapshot.json).",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Gemini model id (default: {DEFAULT_MODEL}).",
    )
    return parser.parse_args()


def load_snapshot(path: Path) -> dict[str, Any]:
    if not path.exists():
        print(f"[orchestrator] snapshot not found: {path}", file=sys.stderr)
        print(
            "[orchestrator] Run the control plane + scripts/ddos.py first to "
            "produce one.",
            file=sys.stderr,
        )
        sys.exit(1)
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def get_client() -> genai.Client:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print(
            "[orchestrator] GEMINI_API_KEY environment variable is not set.",
            file=sys.stderr,
        )
        sys.exit(2)
    return genai.Client(api_key=api_key)


def run_analyzer(
    client: genai.Client,
    model: str,
    snapshot: dict[str, Any],
) -> str:
    user_payload = (
        "TELEMETRY SNAPSHOT (JSON):\n"
        f"{json.dumps(snapshot, indent=2)}"
    )
    config = types.GenerateContentConfig(
        system_instruction=ANALYZER_SYSTEM_PROMPT,
    )
    try:
        response = client.models.generate_content(
            model=model, contents=user_payload, config=config
        )
    except genai_errors.APIError as exc:
        # APIError is the common base of ServerError (5xx) and ClientError
        # (4xx), so this single handler covers both 503 UNAVAILABLE and 429
        # RESOURCE_EXHAUSTED. The narrower ServerError-only catch we had
        # before let 429s crash the worker outright.
        print(
            f"[orchestrator] WARNING: {model} unavailable ({exc}) "
            f"— retrying with {FALLBACK_MODEL}",
            file=sys.stderr,
        )
        response = client.models.generate_content(
            model=FALLBACK_MODEL, contents=user_payload, config=config
        )
    return response.text or ""


def run_strategist(
    client: genai.Client,
    model: str,
    snapshot: dict[str, Any],
    analysis: str,
) -> MitigationStrategy:
    # Burst throttle. Placed at the top of run_strategist (rather than in the
    # callers) so EVERY caller — standalone CLI in main() and the control
    # plane's _ai_worker thread — gets the same protection without each
    # having to remember to sleep. The Analyzer call has already returned by
    # the time we're here, so this delay sits exactly between the two API
    # calls, which is what the token bucket needs to see.
    if BURST_DELAY_SECONDS > 0:
        time.sleep(BURST_DELAY_SECONDS)

    user_payload = (
        "ANALYZER REASONING:\n"
        f"{analysis}\n\n"
        "ORIGINAL SNAPSHOT (for authoritative node IDs and roles):\n"
        f"{json.dumps(snapshot, indent=2)}"
    )
    config = types.GenerateContentConfig(
        system_instruction=STRATEGIST_SYSTEM_PROMPT,
        response_mime_type="application/json",
        response_schema=MitigationStrategy,
    )
    try:
        response = client.models.generate_content(
            model=model, contents=user_payload, config=config
        )
    except genai_errors.APIError as exc:
        # See run_analyzer — APIError covers both 5xx ServerError and 4xx
        # ClientError (incl. 429 RESOURCE_EXHAUSTED).
        print(
            f"[orchestrator] WARNING: {model} unavailable ({exc}) "
            f"— retrying with {FALLBACK_MODEL}",
            file=sys.stderr,
        )
        response = client.models.generate_content(
            model=FALLBACK_MODEL, contents=user_payload, config=config
        )
    # Constrained decoding guarantees response.parsed is a MitigationStrategy.
    # The fallback path covers SDK edge cases where .parsed is None despite a
    # valid response.text.
    parsed = response.parsed
    if isinstance(parsed, MitigationStrategy):
        return parsed
    return MitigationStrategy.model_validate_json(response.text or "{}")


def _print_banner(title: str) -> None:
    print()
    print("=" * 80)
    print(f"  {title}")
    print("=" * 80)


def main() -> int:
    args = parse_args()
    snapshot = load_snapshot(args.snapshot)
    client = get_client()

    trigger = snapshot.get("trigger", {})
    _print_banner("NetShield AI Orchestrator")
    print(f"  snapshot : {args.snapshot}")
    print(f"  model    : {args.model}")
    print(
        f"  trigger  : node {trigger.get('node_id')} "
        f"queue={trigger.get('queue_size'):,} "
        f"threshold={trigger.get('threshold'):,}"
    )

    _print_banner("ANALYZER AGENT — raw reasoning")
    analysis = run_analyzer(client, args.model, snapshot)
    print(analysis)

    _print_banner("STRATEGIST AGENT — structured mitigation plan")
    strategy = run_strategist(client, args.model, snapshot, analysis)
    print(json.dumps(strategy.model_dump(), indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
