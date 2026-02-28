# Skill Sanitizer

**The first open-source AI sanitizer with local semantic detection.**

Commercial AI security tools exist — they all require sending your prompts to their cloud. Your antivirus shouldn't need antivirus.

7 detection layers + code block context awareness + optional LLM semantic judgment. Zero dependencies. Zero cloud calls. Your data never leaves your machine.

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
| 2. Prompt Injection | Instruction override, role hijacking, system prompt override | HIGH-CRITICAL |
| 3. Suspicious Bash | `rm -rf /`, reverse shells, pipe-to-shell, cron modification | MEDIUM-CRITICAL |
| 4. Memory Tampering | Writes to MEMORY.md, SOUL.md, CLAUDE.md, .env files | CRITICAL |
| 5. Context Pollution | Attack patterns disguised as "examples" or "test cases" | MEDIUM-HIGH |
| 6. Trust Abuse | Skill named `safe-*` but contains `eval()`, `rm -rf` | HIGH |
| 7. Encoding Evasion | Unicode homoglyphs, base64 payloads, synonym overrides | HIGH |

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

# Run built-in test suite (15 attack vectors)
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

## License

MIT
