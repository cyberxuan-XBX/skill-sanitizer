# Skill Sanitizer

**The first open-source AI sanitizer with local semantic detection.**

Commercial AI security tools exist — they all require sending your prompts to their cloud. Your antivirus shouldn't need antivirus.

7 detection layers + optional LLM semantic judgment. Zero dependencies. Zero cloud calls. Your data never leaves your machine.

## Why You Need This

- SKILL.md files are **prompts written for AI to execute**
- Attackers hide `ignore previous instructions` in "helpful" skills
- Base64-encoded reverse shells look like normal text
- Names like `safe-defender` can contain `eval(user_input)`
- Your agent doesn't know it's being attacked — it just obeys

## The 7 Layers

| Layer | What It Catches | Severity |
|-------|----------------|----------|
| 1. Kill-String | Credential patterns (API keys, tokens) | CRITICAL |
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

# Run built-in test suite (10 attack vectors)
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

## Real-World Stats

Tested against 261 ClawHub skills:
- **16-20% flagged** (HIGH or CRITICAL)
- Most common: `privilege_escalation`, `ssh_connection`, `pipe_to_shell`
- Zero false negatives against 10 known attack vectors

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
