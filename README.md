# Skill Sanitizer

**The first open-source AI sanitizer with local semantic detection.**

Commercial AI security tools exist — they all require sending your prompts to their cloud. Your antivirus shouldn't need antivirus.

7 built-in detection layers + [ATR](https://github.com/Agent-Threat-Rule/agent-threat-rules) external rule loading + code block context awareness. Zero cloud calls. Your data never leaves your machine.

## Why You Need This

- SKILL.md files are **prompts written for AI to execute**
- Attackers hide `ignore previous instructions` in "helpful" skills
- Base64-encoded reverse shells look like normal text
- Names like `safe-defender` can contain `eval(user_input)`
- Your agent doesn't know it's being attacked — it just obeys

## The 7 Layers

| Layer | What It Catches | Severity |
|-------|----------------|----------|
| 1. Kill-String | Actual credential values (API keys, tokens) | CRITICAL |
| 2. Prompt Injection | Instruction override, role hijacking, telemetry pipelines, eval subshells, analytics harvesting | HIGH-CRITICAL |
| 3. Suspicious Bash | `rm -rf /`, reverse shells, pipe-to-shell, cron modification, symlink mass install | MEDIUM-CRITICAL |
| 4. Memory Tampering | Writes to MEMORY.md, SOUL.md, CLAUDE.md, .env (CRITICAL) vs generic .md (MEDIUM) | MEDIUM-CRITICAL |
| 5. Context Pollution | Attack patterns disguised as "examples" or "test cases" | MEDIUM-HIGH |
| 6. Trust Abuse | Skill named `safe-*` but contains `eval()`, `rm -rf` | HIGH |
| 7. Encoding Evasion | Unicode homoglyphs, base64 payloads, synonym overrides | HIGH |
| 8. ATR Rules | External ATR YAML rules (multi-agent, tool poisoning, supply chain, OWASP Agentic) | varies |

## Usage

### Python

```python
from skill_sanitizer import sanitize_skill

result = sanitize_skill(skill_content, "skill-name")

if result["risk_level"] in ("HIGH", "CRITICAL"):
    print(f"BLOCKED: {result['risk_level']} (score={result['risk_score']})")
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f.get('pattern', '?')}")
else:
    clean_content = result["content"]
```

### CLI

```bash
# Scan a file
python3 skill_sanitizer.py scan skill-name < SKILL.md

# Run built-in test suite (21 attack vectors)
python3 skill_sanitizer.py test
```

## Risk Levels

| Level | Score | Action |
|-------|-------|--------|
| CLEAN | 0 | Safe to process |
| LOW | 1-3 | Safe, minor flags |
| MEDIUM | 4-9 | Proceed with caution |
| HIGH | 10-19 | Block by default |
| CRITICAL | 20+ | Block immediately |

## What's New in v2.3

- **ATR rule loading** — load external [ATR (Agent Threat Rules)](https://github.com/Agent-Threat-Rule/agent-threat-rules) YAML rules via `--atr-rules <path>`
- **Layer 8: ATR scanning** — ATR rules run as an additional detection layer alongside built-in 7 layers
- **81→86+ rules** — built-in 7 layers + entire ATR ruleset (multi-agent attacks, tool poisoning, supply chain, OWASP Agentic Top 10)
- **Smart code block filtering** — ATR matches inside code blocks are skipped (ATR is designed for runtime; code examples ≠ attacks)
- **Contributed 5 rules upstream** — [PR #5](https://github.com/Agent-Threat-Rule/agent-threat-rules/pull/5) to ATR covering memory tampering, credential pipe exfil, homoglyph evasion, context pollution, stealth persistence

```bash
# Clone ATR rules
git clone https://github.com/Agent-Threat-Rule/agent-threat-rules.git atr-rules

# Scan with ATR (86+ rules)
python3 skill_sanitizer.py --atr-rules atr-rules/rules scan skill-name < SKILL.md

# Test with ATR
python3 skill_sanitizer.py --atr-rules atr-rules/rules test
```

Requires `pip install pyyaml` for ATR loading. Without `--atr-rules`, works exactly like v2.2 (zero dependencies).

## What's New in v2.2

- **Telemetry pipeline detection** — catches `telemetry-log`, `telemetry-sync`, and silent data upload scripts
- **Analytics harvesting** — flags `analytics/*.jsonl`, `eureka.jsonl`, `skill-usage.jsonl` local data collection
- **eval subshell detection** — `eval "$(cmd)"` patterns now flagged as HIGH
- **External analytics services** — detects Supabase, PostHog, Mixpanel, Amplitude, Segment
- **Device fingerprinting** — `installation-id` / `install-id` patterns caught
- **Smarter file write severity** — writes to MEMORY.md/SOUL.md/CLAUDE.md/.env stay CRITICAL, generic `.md` writes downgraded to MEDIUM
- **Symlink mass installation** — `ln -sf` and `find -exec ln` patterns detected
- **21 test vectors** (up from 15)

Tested against [gstack](https://github.com/garrytan/gstack) (63K stars, 33 skills):
- v2.1: caught `memory_tamper` but missed telemetry, eval pipelines, and analytics collection
- v2.2: catches all of the above — telemetry pipeline (30 hits), analytics collection (33), eval subshell (28)

## What's New in v2.1

- **Code block awareness** — patterns inside \`\`\`code blocks\`\`\` get severity reduced (teaching ≠ attacking)
- **Smarter credential detection** — env var *names* (ANTHROPIC_API_KEY) are MEDIUM, actual *values* (sk-ant-...) are CRITICAL
- **Pipe-based exfiltration** — `echo $API_KEY | curl ...` caught as CRITICAL
- **85% fewer false positives** — re-tested 20 previously blocked skills, 17 correctly downgraded

## Real-World Stats

Tested against 550 ClawHub skills:
- **29% flagged** (HIGH or CRITICAL) with v2.0
- **85% false positive reduction** with v2.1 improvements
- Most common: `privilege_escalation`, `ssh_connection`, `pipe_to_shell`
- Zero false negatives against 15 known attack vectors

## Design Principles

1. **Scan before LLM, not inside LLM** — by the time your LLM reads it, it's too late
2. **Block and log, don't silently drop** — every block is recorded with evidence
3. **Unicode-first** — normalize all text before scanning (NFKC + homoglyph replacement)
4. **No cloud, no API keys** — runs 100% locally, zero network calls
5. **False positives > false negatives** — better to miss a good skill than let a bad one through

## Install via ClawHub

```bash
clawhub install skill-sanitizer
```

## Related

- [quan](https://github.com/cyberxuan-XBX/quan) — AI partner framework. The thinking layer that goes with the security layer.

## License

MIT
