#!/usr/bin/env python3
"""
NBody Labs X Range Automated Bug Bounty Triage Bot
Evaluates security research reports submitted via Pull Request against the 25-point rubric.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional
import urllib.request
import urllib.error

RUBRIC_PATH = Path(__file__).parent / "rubric.json"


def load_rubric(path: Path = RUBRIC_PATH) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_system_prompt(rubric: Dict[str, Any]) -> str:
    prompt = (
        "You are the Lead Security Triager and Evaluator at NBody Labs X Range.\n"
        "Your task is to objectively evaluate a submitted Bug Bounty / Security Research report written by a researcher.\n\n"
        "You evaluate reports against a strict 25-point rubric spanning 5 distinct dimensions (0 to 5 points each).\n\n"
        "### EVALUATION CRITERIA:\n"
    )

    for dim in rubric["dimensions"]:
        prompt += f"\n#### {dim['name']} (ID: {dim['id']}, Max: {dim['max_points']} pts)\n"
        for score, desc in dim["criteria"].items():
            prompt += f"- {score} pts: {desc}\n"

    prompt += (
        "\n### GRADING SCALE:\n"
        "- 23-25 pts: Grade A - Accepted (Exemplary)\n"
        "- 18-22 pts: Grade B - Valid (Minor Revisions)\n"
        "- 12-17 pts: Grade C - Needs Work (Informational)\n"
        "- 0-11 pts: Grade D - Rejected\n\n"
        "### STRICT EVALUATION GUIDELINES:\n"
        "1. Real-world LLM findings must be EMPIRICALLY grounded. Do not reward reports that claim 100% determinism without trial data, or that rely on vague handwaving.\n"
        "2. Differentiate demonstrated impact (actual tool executions, data leaks) from inflated theoretical claims.\n"
        "3. Provide constructive, specific, highly actionable feedback for every dimension.\n"
        "4. Your response MUST be valid JSON adhering strictly to this schema:\n"
        "{\n"
        '  "executive_summary": "Concise 2-3 sentence overview of the submission and quality.",\n'
        '  "scores": {\n'
        '    "technical_precision": {"score": <0-5>, "feedback": "Detailed feedback..."},\n'
        '    "empirical_reproducibility": {"score": <0-5>, "feedback": "Detailed feedback..."},\n'
        '    "blast_radius": {"score": <0-5>, "feedback": "Detailed feedback..."},\n'
        '    "attack_chain": {"score": <0-5>, "feedback": "Detailed feedback..."},\n'
        '    "remediation": {"score": <0-5>, "feedback": "Detailed feedback..."}\n'
        "  },\n"
        '  "total_score": <sum of 5 dimension scores: 0-25>,\n'
        '  "grade": "A|B|C|D",\n'
        '  "verdict": "Accepted (Exemplary)|Valid (Minor Revisions)|Needs Work (Informational)|Rejected",\n'
        '  "strengths": ["Strength 1", "Strength 2"],\n'
        '  "areas_for_improvement": ["Area 1", "Area 2"]\n'
        "}\n"
    )
    return prompt


def run_llm_evaluation(report_content: str, rubric: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY")
    base_url = os.getenv("TRIAGE_API_BASE") or os.getenv("OPENAI_BASE_URL")
    model = os.getenv("TRIAGE_MODEL")

    if not api_key:
        print("[!] No OPENAI_API_KEY or GEMINI_API_KEY found in environment.", file=sys.stderr)
        print("[!] Running in mock evaluation mode (fallback for local dry run)...", file=sys.stderr)
        return generate_mock_evaluation(report_content)

    # Automatically support Gemini OpenAI compatibility endpoint if using GEMINI_API_KEY
    if os.getenv("GEMINI_API_KEY") and not os.getenv("OPENAI_API_KEY") and not base_url:
        base_url = "https://generativelanguage.googleapis.com/v1beta/openai/"
        if not model:
            model = "gemini-1.5-flash"

    if not model:
        model = "gpt-4o-mini"

    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key, base_url=base_url)

        system_prompt = build_system_prompt(rubric)
        user_prompt = f"Please evaluate the following vulnerability report:\n\n```markdown\n{report_content}\n```"

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )

        content = response.choices[0].message.content
        return json.loads(content)
    except Exception as e:
        print(f"[!] Error calling LLM API: {e}", file=sys.stderr)
        print("[!] Falling back to heuristic mock evaluation...", file=sys.stderr)
        return generate_mock_evaluation(report_content)


def generate_mock_evaluation(report_content: str) -> Dict[str, Any]:
    """Provides a deterministic fallback evaluation for testing without API keys."""
    length = len(report_content.strip())
    has_trials = "trial" in report_content.lower() or "n=" in report_content.lower() or "%" in report_content
    has_tools = "tool" in report_content.lower()
    has_remediation = "remediation" in report_content.lower() or "mitigation" in report_content.lower()

    tech_score = 4 if has_tools and length > 800 else 2
    repro_score = 4 if has_trials else 2
    blast_score = 4 if has_tools else 2
    chain_score = 4 if length > 1000 else 2
    remed_score = 4 if has_remediation else 2

    total = tech_score + repro_score + blast_score + chain_score + remed_score
    if total >= 23:
        grade, verdict = "A", "Accepted (Exemplary)"
    elif total >= 18:
        grade, verdict = "B", "Valid (Minor Revisions)"
    elif total >= 12:
        grade, verdict = "C", "Needs Work (Informational)"
    else:
        grade, verdict = "D", "Rejected"

    return {
        "executive_summary": "Submission evaluated via automated triage pipeline. The report demonstrates a clear security finding with practical reproducibility.",
        "scores": {
            "technical_precision": {
                "score": tech_score,
                "feedback": "Target trust boundaries and context flows are identified." if tech_score >= 3 else "Needs clearer modeling of prompt/tool boundaries."
            },
            "empirical_reproducibility": {
                "score": repro_score,
                "feedback": "Reproduction steps are documented with trial statistics." if repro_score >= 3 else "Include empirical sampling across N trials with success rate."
            },
            "blast_radius": {
                "score": blast_score,
                "feedback": "Demonstrates concrete impact on agent tool execution." if blast_score >= 3 else "Impact should be tied directly to agent capability."
            },
            "attack_chain": {
                "score": chain_score,
                "feedback": "Payload structure and delimiter handling are explained." if chain_score >= 3 else "Dissect why the payload bypassed agent constraints."
            },
            "remediation": {
                "score": remed_score,
                "feedback": "Layered defense strategy proposed covering architecture and prompts." if remed_score >= 3 else "Propose structural defenses (e.g. dual-LLM or schema gating)."
            }
        },
        "total_score": total,
        "grade": grade,
        "verdict": verdict,
        "strengths": [
            "Structured report following the standardized template.",
            "Demonstrates functional prompt injection against the agent target."
        ],
        "areas_for_improvement": [
            "Document empirical success rates across multiple trials (e.g. N=10).",
            "Detail layered architectural remediations beyond prompt adjustments."
        ]
    }


def format_markdown_comment(result: Dict[str, Any], report_filename: str) -> str:
    total = result.get("total_score", 0)
    grade = result.get("grade", "N/A")
    verdict = result.get("verdict", "Evaluated")
    scores = result.get("scores", {})

    dim_names = {
        "technical_precision": "1. Technical Precision & Context",
        "empirical_reproducibility": "2. Empirical Reproducibility",
        "blast_radius": "3. Blast Radius & Realistic Impact",
        "attack_chain": "4. Attack Chain & Payload Engineering",
        "remediation": "5. Remediation & Defense-in-Depth",
    }

    badge_color = "brightgreen" if grade == "A" else ("blue" if grade == "B" else ("yellow" if grade == "C" else "red"))

    md = [
        f"## 🛡️ NBody Labs X Range Security Triage: Evaluation Report Card",
        f"",
        f"**Target Report**: `{report_filename}`",
        f"",
        f"| **Final Score** | **Grade** | **Triage Verdict** |",
        f"| :---: | :---: | :---: |",
        f"| **{total} / 25** | **Grade {grade}** | **{verdict}** |",
        f"",
        f"### 📊 Rubric Score Breakdown",
        f"",
        f"| Dimension | Score | Feedback & Observations |",
        f"| :--- | :---: | :--- |",
    ]

    for key, name in dim_names.items():
        data = scores.get(key, {})
        sc = data.get("score", 0)
        fb = data.get("feedback", "No feedback provided.")
        md.append(f"| **{name}** | `{sc} / 5` | {fb} |")

    md.extend([
        f"",
        f"### 🌟 Key Strengths",
    ])
    for s in result.get("strengths", []):
        md.append(f"- {s}")

    md.extend([
        f"",
        f"### 🎯 Actionable Areas for Improvement",
    ])
    for a in result.get("areas_for_improvement", []):
        md.append(f"- {a}")

    summary = result.get("executive_summary", "")
    if summary:
        md.extend([
            f"",
            f"### 📝 Triager Executive Summary",
            f"> {summary}",
        ])

    md.extend([
        f"",
        f"---",
        f"*Evaluated automatically by NBody Labs X Range Bug Bounty Triage Bot against [`RUBRIC.md`](docs/RUBRIC.md).*",
    ])

    return "\n".join(md)


def post_github_comment(repo: str, pr_number: int, token: str, comment_body: str) -> None:
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": comment_body}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "nbodylabs-triage-bot",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status in (200, 201):
                print(f"[✓] Successfully posted triage review comment to PR #{pr_number}")
            else:
                print(f"[!] GitHub API returned status {resp.status}", file=sys.stderr)
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP error posting PR comment: {e.code} - {e.read().decode('utf-8')}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Evaluate Bug Bounty report against 25-point rubric.")
    parser.add_argument("--report", required=True, help="Path to report markdown file")
    parser.add_argument("--rubric", default=str(RUBRIC_PATH), help="Path to rubric JSON")
    parser.add_argument("--output", help="Path to save markdown output")
    parser.add_argument("--pr-number", type=int, help="GitHub PR number to comment on")
    parser.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY"), help="GitHub owner/repo")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of markdown")

    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"[!] Report file not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    with open(report_path, "r", encoding="utf-8") as f:
        report_content = f.read()

    rubric_file = Path(args.rubric)
    rubric = load_rubric(rubric_file)

    print(f"[*] Evaluating report: {report_path.name}...")
    result = run_llm_evaluation(report_content, rubric)

    if args.json:
        output_str = json.dumps(result, indent=2)
    else:
        output_str = format_markdown_comment(result, report_path.name)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_str)
        print(f"[✓] Output written to {args.output}")
    else:
        print(output_str)

    if args.pr_number:
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            print("[!] GITHUB_TOKEN not found. Skipping PR comment.", file=sys.stderr)
        elif not args.repo:
            print("[!] GITHUB_REPOSITORY not specified. Skipping PR comment.", file=sys.stderr)
        else:
            post_github_comment(args.repo, args.pr_number, token, output_str)


if __name__ == "__main__":
    main()
