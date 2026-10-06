# bb-scan

A source-code security triage pipeline for bug bounty and vulnerability
disclosure workflows. Clones a repository, runs multiple Semgrep rulesets,
classifies findings by file path and attacker model, and produces a ranked
triage report with LLM-assisted analysis and mechanical verification.

## What it does

1. Clones the target repository (shallow, --depth 1)
2. Runs Semgrep with multiple public rulesets plus per-language rules
3. Tags each finding by file path (CI, test, demo, build, SDK, web)
4. Extracts GitHub Actions context (on:, job if:, permissions)
5. Optional tier 1: fast model filters out obviously irrelevant leads
6. Tier 2: deep model produces source/sink/validation explanations
7. Mechanical verification: rejects model claims that cannot be quoted
   from the source. Caps the verdict at unverified when the flow fails
8. Auto-resolves missing context by fetching function definitions
9. Groups results and writes a ranked markdown report plus a
   second-opinion pack for a stronger model

## Output

- reports/<repo>.triage.md - ranked triage report
- reports/<repo>.triage.json - machine-readable results
- reports/<repo>.second-opinion.md - packet for a stronger model
- reports/<repo>.attack-surface.md - route-like entry points
- repos/_rule-history.jsonl - accumulated rule performance

## Requirements

- PowerShell 7+ (Windows, macOS, or Linux)
- Semgrep 1.178+ on PATH
- Ollama running locally with qwen2.5-coder:7b and optionally qwen2.5-coder:3b
- Git on PATH

## Usage

    .\bb-scan-v3.5.ps1 -RepoUrl https://github.com/OWNER/REPO -RepoType service -MaxLeads 40

Optional flags:

- -UseFastFilter : enable tier-1 model filtering
- -RepoType auto|service|library|cli_desktop|infra|vscode_extension
- -MaxLeads N : cap the number of leads triaged
- -NoAutoResolve : disable missing-context resolution
- -NoRuleCaps : disable auto-suppression from rule history

## Design principles

- Every item is a lead, not a finding. The tool tells a human where to
  look, not what is broken.
- Mechanical verification over model confidence. If the model cannot
  quote the source line that connects a source to a sink, the lead is
  downgraded to unverified.
- Rule history as a feedback loop. Rules that have produced no signal
  across prior scans are capped automatically.
- Attacker model per repo type. A library, a service, and a desktop
  tool have different threat models and the tool reflects that.

## Limitations

This tool produces leads for manual review. It does not confirm
vulnerabilities. On mature, well-audited projects the majority of leads
will be false positives that must be ruled out by reading the code.