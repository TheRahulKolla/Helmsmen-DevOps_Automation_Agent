"""
agent.py - Helmsmen's ReAct loop.

Adapted from Agent/agent.py. Key differences:
  - No query_planner (single structured task, not free-form research)
  - No trim_history (runs are short; rarely >15 tool iterations)
  - Uses claude-sonnet-4-6 for better reasoning on severity classification
  - Returns a DevOps-shaped result dict (issues_created, slack_posted, etc.)
"""

import os
import time
from datetime import datetime, timezone

import anthropic
from dotenv import load_dotenv

from tools import get_tool_definitions, execute_tool
from prompts import SYSTEM_PROMPT
import state

load_dotenv()

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

# Sonnet: the reasoning here (severity classification, when to create issues,
# when to search) is heavier than the Agent project's research task.
MODEL = "claude-sonnet-4-6"


def run_agent(owner: str, repo: str, max_iterations: int = 20) -> dict:
    """
    Run the DevOps health-check ReAct loop against a single repository.

    Returns:
        {
          "status":          "success" | "max_iterations_reached" | "error",
          "owner":           str,
          "repo":            str,
          "iterations":      int,
          "duration_sec":    float,
          "issues_created":  int,
          "issues_skipped":  int,
          "slack_posted":    bool,
          "final_message":   str (Claude's closing text)
        }
    """
    start = time.time()
    state.set_last_run()

    print(f"\n{'=' * 60}")
    print(f"HELMSMEN RUN: {owner}/{repo}")
    print(f"{'=' * 60}")

    user_message = (
        f"Perform a full health check on the GitHub repository {owner}/{repo}. "
        f"Today is {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}. "
        f"Follow your standard workflow: gather CI status, scan dependencies, "
        f"check stale PRs, create issues for actionable findings, then post a "
        f"Slack digest to the channel {os.environ.get('SLACK_CHANNEL', '#devops-alerts')}."
    )

    messages = [{"role": "user", "content": user_message}]
    issues_created = 0
    issues_skipped = 0
    slack_posted = False
    iteration = 0

    while iteration < max_iterations:
        iteration += 1
        print(f"\n--- Iteration {iteration} ---")

        # 4096 is enough to emit several tool calls with verbose issue bodies
        # plus a Slack digest in one turn. Overkill for a gather-only turn,
        # but Anthropic only bills for tokens actually emitted — not the ceiling.
        max_tokens = 4096

        # Retry up to twice on max_tokens stop — double the budget each time.
        response = None
        for attempt, budget in enumerate([max_tokens, 8192, 16384]):
            try:
                response = client.messages.create(
                    model=MODEL,
                    max_tokens=budget,
                    system=SYSTEM_PROMPT,
                    tools=get_tool_definitions(),
                    messages=messages,
                )
            except anthropic.APIError as e:
                return _error_result(owner, repo, iteration, start,
                                     f"Anthropic API error: {e}")
            if response.stop_reason != "max_tokens":
                break
            print(f"  (hit max_tokens at {budget}; retrying with bigger budget)")

        print(f"Stop reason: {response.stop_reason}")

        # ── Case A: done, emit final text ──
        if response.stop_reason == "end_turn":
            final_text = "".join(b.text for b in response.content if hasattr(b, "text"))
            print("\nHELMSMEN DONE.")
            return {
                "status": "success",
                "owner": owner,
                "repo": repo,
                "iterations": iteration,
                "duration_sec": round(time.time() - start, 2),
                "issues_created": issues_created,
                "issues_skipped": issues_skipped,
                "slack_posted": slack_posted,
                "final_message": final_text,
            }

        # ── Case B: Claude wants to use one or more tools ──
        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})
            tool_results = []

            for block in response.content:
                if block.type != "tool_use":
                    continue
                name = block.name
                tool_input = block.input
                print(f"  Tool: {name}({_preview_input(tool_input)})")

                result = execute_tool(name, tool_input)
                print(f"  Result: {result[:150].replace(chr(10), ' ')}...")

                # Track outcomes for the result dict
                if name == "create_github_issue":
                    if result.startswith("Issue created"):
                        issues_created += 1
                    elif result.startswith("SKIPPED"):
                        issues_skipped += 1
                elif name == "post_slack_digest" and result.startswith("Slack message posted"):
                    slack_posted = True

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })

            messages.append({"role": "user", "content": tool_results})
            continue

        # ── Case C: unexpected stop reason ──
        return _error_result(owner, repo, iteration, start,
                             f"Unexpected stop_reason: {response.stop_reason}")

    # Hit max_iterations without end_turn
    return {
        "status": "max_iterations_reached",
        "owner": owner,
        "repo": repo,
        "iterations": max_iterations,
        "duration_sec": round(time.time() - start, 2),
        "issues_created": issues_created,
        "issues_skipped": issues_skipped,
        "slack_posted": slack_posted,
        "final_message": "",
    }


def _preview_input(tool_input: dict) -> str:
    """Short repr of tool input for logging."""
    parts = []
    for k, v in tool_input.items():
        vs = str(v)
        if len(vs) > 60:
            vs = vs[:57] + "..."
        parts.append(f"{k}={vs}")
    return ", ".join(parts)


def _error_result(owner, repo, iteration, start, msg) -> dict:
    print(f"ERROR: {msg}")
    return {
        "status": "error",
        "owner": owner,
        "repo": repo,
        "iterations": iteration,
        "duration_sec": round(time.time() - start, 2),
        "issues_created": 0,
        "issues_skipped": 0,
        "slack_posted": False,
        "final_message": msg,
    }
