# CTF Agent — Stage 1+2+3+4+5+6: Conversational AI + Challenge Analysis + Exploitation + Autonomous Reasoning

A command-line AI agent with normal conversational capabilities, supporting multiple LLM providers through adapter pattern, plus a modular tool system for analyzing authorized CTF challenge files stored in the project workspace, inspecting authorized CTF web challenges, and running autonomous investigations with planning, evidence logging, session memory, and structured reports.

## Stage 1 Features

- Normal conversational AI chat loop
- Support for OpenRouter and OpenCode providers via separate adapters
- Environment variable configuration for API keys and model names
- Configurable Ling 3.0 as the initial model
- Conversation history management
- Command support: `/exit`, `/reset`, `/model`, `/provider`, `/help`
- Error handling for: invalid API key, unsupported model, provider unavailable, rate limit, payment required, timeout, empty response

## Stage 2 Features

- Modular tool system with a tool registry, metadata, argument validation, consistent result format, and execution timeouts
- Centralized workspace security that restricts all file operations to `challenges/` and blocks path traversal
- Local file tools: `list_files`, `read_text_file`, `inspect_file`, `search_files`, `calculate_file_hash`
- Data decoding tool: `decode_data` (Base64, hex, URL, ROT13, binary, auto-detect)
- Restricted command execution tool: `run_ctf_command` with an allowlist (file, strings, xxd, hexdump, readelf, objdump, nm, ldd, grep, rg, python, python3), shell operator blocking, argument validation, timeouts, and output truncation
- Tool-calling support in both provider adapters with one internal tool-call format
- Configurable maximum agent steps to prevent infinite tool loops
- New command: `/tools` (lists tools and OS availability)
- Updated `/help` to explain challenge file analysis
- Agent system prompt with tool usage rules

## Stage 3 Features (Web Inspection)

- Safe HTTP tools: `http_request` (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS), `inspect_webpage`, `extract_web_elements`, `compare_http_responses`, `manage_http_session`
- URL security validation: blocks non-http(s) schemes, embedded credentials, localhost/private/metadata IPs, redirect abuse, and sensitive ports
- Persistent HTTP session with cookie jar and default headers; sensitive cookies/headers masked in output
- HTML parsing: links, forms, inputs, hidden fields, scripts, comments, iframes, buttons, meta, visible text, API routes, technology detection
- Config: `HTTP_TIMEOUT_SECONDS`, `HTTP_MAX_REDIRECTS`, `HTTP_USER_AGENT`, `HTTP_ALLOW_PRIVATE_TARGETS`, `HTTP_MAX_BODY_CHARS`

## Stage 4 Features (Skills)

- Modular skill system: loader, registry, router, context injection, and optional GitHub sync
- 35 bundled skills (5 common, 17 web, 13 binary) as Markdown + YAML front matter under `skills/`
- Deterministic local scoring for skill selection (11 weighted factors); no extra model call
- Commands: `/skills`, `/skill <id>`, `/skill auto`, `/skill off`, `/skill clear`
- CLI flag: `--sync-skills` (git clone/fetch via subprocess, list argv only)
- Context limits: max active skills (default 5), max chars per skill (default 4000)
- Skills are operational hints only — never evidence; cannot override safety rules
- Config vars: `SKILLS_DIRECTORY`, `ENABLE_SKILLS`, `MAX_ACTIVE_SKILLS`, `MAX_SKILL_CONTEXT_CHARS`, `SKILL_AUTO_SELECTION`, `SKILL_MIN_SCORE`, `SKILLS_REPOSITORY_URL`, `SKILLS_REPOSITORY_BRANCH`, `SKILLS_SYNC_DIRECTORY`

## Stage 5 Features (Exploitation Helpers)

### Web tools (`tools/web_tools.py`)
- HTTP method wrappers: `http_get`, `http_post`, `http_put`, `http_delete`
- Cookie/session management: `manage_cookies` (show/clear/set/remove)
- Header analysis: `analyze_headers` (all headers + security header presence report, sensitive values masked)
- Resource readers: `read_robots_txt`, `read_sitemap_xml`
- HTML extraction: `extract_links_from_page`, `extract_forms_from_page`, `extract_javascript_from_page`, `extract_html_comments`
- Discovery: `enumerate_directories`, `discover_api_endpoints`, `discover_hidden_endpoints` (small conservative built-in wordlists — no brute-force scanning)

### Binary tools (`tools/binary_tools.py`)
- `binary_file_info` (file), `binary_strings` (strings), `binary_readelf` (readelf), `binary_objdump` (objdump), `binary_symbols` (nm), `binary_libraries` (ldd), `binary_hexdump` (xxd/hexdump), `binary_checksec` (checksec if installed)
- `analyze_binary` runs the full workflow: file → checksec → strings → readelf → objdump → symbols → interesting strings → possible vulnerability notes
- Every helper returns a friendly error when the command is unavailable instead of crashing; runs with `shell=False`

### Decoders (`tools/decoder_tools.py`)
- Extended `decode_data`: Base64, hex, URL, ROT13, binary, **octal, decimal, ASCII, UTF-8, JWT, Gzip, Zlib**, and auto-detection
- `decode_jwt` / `parse_jwt` decode header/payload (signature never verified — decoder only)
- The original `tools/data_tools.decode_data` is kept intact for backward compatibility

### Recon tools (`tools/recon_tools.py`)
- Page finders: `find_login_page`, `find_admin_page`
- Endpoint finders: `find_api_endpoints`, `find_backup_files`
- Technology detection: `detect_framework`, `detect_server`, `detect_technology_stack`
- Content extraction: `extract_emails`, `extract_version_info`

### Prompt & workflows (`agent/prompts.py`)
- Experienced-CTF-player system prompt: never hallucinate flags, never guess, always verify with tools, prefer evidence, think step by step, report only confirmed findings, explain next steps
- Documented Web workflow: inspect page → headers → cookies → robots.txt → sitemap → forms → JS → endpoints → auth → params → vuln classes → report
- Documented Binary workflow: file → checksec → strings → readelf → objdump → symbols → interesting strings → vulns → report

## Stage 6 Features (Autonomous Reasoning)

### Planner (`agent/planner.py`)
- `Planner` generates an ordered investigation plan BEFORE any tool executes
- Steps are derived per challenge type, filtered to tools available in the registry
- Step tracking: pending → done as the agent uses their tools; `/plan` shows status
- `next_recommended_step()` powers the report's Recommended Next Step section

### Workflow manager (`agent/workflow.py`)
- Automatic challenge type detection: Web, Binary, Crypto, Forensics, Misc
- Detection combines the user request, filenames, extensions, and tool observations with keyword/extensions scoring and a confidence score
- Per-type investigation workflows with recommended tool sequences
- `recommended_tools()` = automatic tool selection based on challenge type + evidence (recommended tools are listed first in the tool definitions sent to the model; all tools remain available)
- `evaluate_progress()` decides whether more investigation is required after each tool execution (flag confirmed, plan complete, or steps remain)

### Retry logic (`tools/retry.py`)
- `execute_with_retry()` transparently retries transient failures: timeouts, connection resets/refused, 5xx server errors, redirect loops, temporary network errors
- Permanent failures (validation/security errors) are never retried
- Configurable via `MAX_TOOL_RETRIES` and `TOOL_RETRY_DELAY_SECONDS`

### Session memory (`agent/memory.py`)
- Lightweight, thread-safe, deduplicated, size-capped store
- Categories: URLs, endpoints, cookies (names only — values never stored), technologies, decoded values, files analyzed, flags, notes
- `remember_tool_result()` extracts facts from tool output automatically (regex-based, conservative)

### Evidence log (`agent/evidence.py`)
- Every tool result is recorded with source tool, arguments, output excerpt, success/failure, and flag matches
- `confirmed_findings()` derives findings strictly from SUCCESSFUL tool outputs
- A flag is only "Confirmed" when the exact value appears in a successful tool result output
- `format_structured_report()` builds the final response:
  - Confirmed Findings
  - Evidence
  - Flag Status (Confirmed / Not Confirmed)
  - Recommended Next Step

### Agent loop (`agent/chat_agent.py`)
- `start_investigation()` detects the challenge type and plans before tool execution
- Every tool result is recorded to evidence + memory and advances the plan
- Transient tool failures are retried automatically in the loop
- Progress is evaluated after every tool execution
- The final response is the model text plus the auto-generated structured Investigation Report
- New commands: `/plan`, `/memory`, `/evidence`, `/status`
- `/reset` clears history, memory, evidence, and the plan
- Config: `ENABLE_AUTONOMOUS_MODE`, `MAX_TOOL_RETRIES`, `TOOL_RETRY_DELAY_SECONDS`, `ENABLE_SESSION_MEMORY`, `MAX_EVIDENCE_ENTRIES`

## Stage 7 Features (CTF Specialist Knowledge)

### Specialist framework (`specialists/`)

- 17 evidence-driven specialists (11 web + 6 binary) with structured results:
  specialist, hypothesis, tools used, confirmed observations, rejected
  hypotheses, raw evidence, flag status, suggested next specialist, and
  low-risk verification steps (spec 15).
- **Web specialists**: SQL injection, authentication/session, JWT,
  SSTI, file inclusion/path traversal, JavaScript/API analysis, upload
  analysis, GraphQL, WebSocket, race condition, PHP type juggling/
  object injection.
- **Binary specialists**: triage, buffer overflow, format string,
  ret2win, ROP analysis, pwntools runner.
- **Specialist router** (`specialists/router.py`) selects specialists from
  challenge category, evidence, file types, error messages, parameters,
  and protections — it never runs every specialist blindly (spec 13).
- Specialists never fabricate findings: confirmed observations come only
  from successful tool output; a flag is confirmed only when it appears
  in a tool result (spec 15).

### Web tooling (spec 6, `tools/js_analysis.py`)

- `analyze_javascript_url` / `analyze_javascript_file` / `analyze_javascript_text`:
  extract endpoints, API base URLs, secrets/tokens, source-map references,
  fetch/XHR calls, GraphQL endpoints, WebSocket URLs, hidden routes,
  client-side authorization logic, and hardcoded credentials.
- `beautify_javascript`: dependency-free minified-JS beautifier.
- `search_javascript_file` / `search_javascript_text`: regex search with
  line context. Output is capped to relevant matches only.

### Binary exploitation tooling (specs 9-12, `tools/binary_pwn.py`)

- `pwn_cyclic` / `pwn_cyclic_find`: De Bruijn-style cyclic patterns
  (pure Python).
- `pwn_pack` / `pwn_unpack`: integer packing (8/16/32/64-bit, endianness).
- `pwn_crash_analyze`: cyclic input -> local crash -> overwrite offset
  (spec 10), `pwn_verify_offset` to confirm it. Works only on files inside
  the challenge workspace with short timeouts.
- `pwn_analyze_ret2win`: arch + win function + offset + validated payload
  plan (spec 11). Addresses are never invented.
- `pwn_find_win_function`, `pwn_got_plt`, `pwn_find_gadgets`,
  `pwn_elf_info`, `pwn_format_string_analysis`.

### Optional pwntools (spec 9, `tools/pwn_session.py`)

- `pwn_session_start` (local process inside workspace, or remote connection
  to a USER-PROVIDED authorized CTF host/port), `pwn_session_send`,
  `pwn_session_recv`, `pwn_session_wait_prompt`, `pwn_session_close`,
  `pwn_status`. Requires `pip install pwntools` and `ENABLE_PWNTOOLS=true`.
  Pure-Python helpers work without pwntools.

### Resource limits (spec 16, `specialists/limits.py`)

- Maximum specialist calls, HTTP requests, command executions, retries,
  output size, per-tool timeout, global challenge timeout, and
  duplicate-action detection, enforced inside the agent loop.
- When a limit is reached the agent returns the strongest confirmed
  evidence plus the next recommended action.

### Knowledge files (spec 14)

- 11 new concise skill files added under `skills/web/` and `skills/binary/`
  (JWT, GraphQL, WebSocket, race condition, PHP type juggling, PHP object
  injection, JS secrets, ret2win, crash-offset, pwntools, GOT/PLT), each
  with when-to-use, required evidence, safe first checks, common false
  positives, tools, and stop conditions.

### New commands

- `/specialists` — list specialists and current recommendations
- `/specialists <name>` — run one specialist explicitly (counted against
  `MAX_SPECIALIST_CALLS`)
- `/limits` — show resource usage and limits
- Specialist guidance is also injected into the system prompt and final
  Investigation Report automatically.

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env` and fill in your API keys:

```bash
cp .env.example .env
```

Then set the environment variables:

```bash
export LLM_PROVIDER=openrouter
export OPENROUTER_API_KEY=sk-or-...
export OPENROUTER_MODEL=ling-3.0
export CTF_WORKSPACE=challenges
export MAX_AGENT_STEPS=10
export TOOL_TIMEOUT_SECONDS=30
export MAX_TOOL_OUTPUT_CHARS=4096
```

Skill system (optional):

```bash
export ENABLE_SKILLS=true
export SKILLS_DIRECTORY=skills
export MAX_ACTIVE_SKILLS=5
export MAX_SKILL_CONTEXT_CHARS=4000
export SKILL_AUTO_SELECTION=true
export SKILL_MIN_SCORE=1.0
# Optional GitHub sync:
export SKILLS_REPOSITORY_URL=https://github.com/user/ctf-skills.git
export SKILLS_REPOSITORY_BRANCH=main
export SKILLS_SYNC_DIRECTORY=skills/downloaded
```

Stage 6 autonomous reasoning (optional):

```bash
export ENABLE_AUTONOMOUS_MODE=true
export MAX_TOOL_RETRIES=2
export TOOL_RETRY_DELAY_SECONDS=0.5
export ENABLE_SESSION_MEMORY=true
export MAX_EVIDENCE_ENTRIES=200
```

Stage 7 specialists and limits (optional):

```bash
export ENABLE_SPECIALISTS=true
export SPECIALIST_MIN_SCORE=0.25
export MAX_SPECIALIST_SUGGESTIONS=3
export MAX_SPECIALIST_CALLS=12
export MAX_HTTP_REQUESTS=40
export MAX_COMMAND_EXECUTIONS=30
export MAX_DUPLICATE_ACTIONS=3
export DUPLICATE_ACTION_WINDOW=90
export GLOBAL_CHALLENGE_TIMEOUT_SECONDS=1800
# Optional pwntools (spec 9):
#   pip install pwntools
#   export ENABLE_PWNTOOLS=true
```

## Using Challenge Files

Place challenge files inside:

```
challenges/<challenge-name>/
```

Then ask the agent things like:

- "List all files in the test challenge."
- "Read challenges/test/message.txt and report confirmed findings."
- "Inspect challenges/test/sample.bin."
- "Decode the Base64 content in challenges/test/encoded.txt."
- "Run strings on challenges/test/sample.bin."
- "Calculate the SHA-256 hash of challenges/test/sample.bin."

The agent uses tools automatically and only reports findings supported by tool output.

## Using the Exploitation Tools

Web (authorized CTF targets):

- "GET http://target.example/ and analyze the headers."
- "Read the robots.txt and sitemap.xml for http://target.example/."
- "Extract all forms, JavaScript, and HTML comments from http://target.example/."
- "Enumerate common directories and discover API/hidden endpoints."
- "Decode this JWT: <token>."

Binary (files inside the workspace):

- "Run the full binary analysis on test/sample.bin."
- "Check the ELF headers and symbols of test/sample.bin."
- "Hex dump the first 256 bytes of test/sample.bin."
- "Find interesting strings and possible vulnerabilities in test/sample.bin."

Autonomous investigation:

- Just describe the challenge: "binary pwn challenge, buffer overflow in test/sample.bin" — the agent detects the type, plans the investigation, selects tools, records evidence, and returns a structured report.
- "web challenge: SQL injection in the login form at http://target.example/" — same autonomous flow for web.
- Use `/status` to see challenge type, plan progress, evidence, memory, and flag status at any time.
- Use `/plan`, `/memory`, `/evidence` to inspect the internal state.

Stage 7 specialists:

- "Use the SQL injection specialist on the evidence collected so far."
- "/specialists" lists the recommended specialists for current evidence.
- "/specialists web.jwt" runs the JWT specialist explicitly.
- "/limits" shows HTTP/command/specialist usage against limits.
- "Analyze the JavaScript at http://target.example/app.js for endpoints and secrets."
- "Find the overwrite offset for challenges/test/sample.bin with cyclic input."
- "Is there a win function in sample.bin? Build a ret2win payload plan."

## Running the Agent

```bash
python main.py
```

Commands:
- `/exit` — quit
- `/reset` — clear conversation history, memory, evidence, and plan
- `/model <name>` — switch model
- `/provider <openrouter|opencode>` — switch provider
- `/session` — show a safe summary of the current HTTP session
- `/skills` — list loaded skills by category
- `/skill <id>` / `/skill auto` / `/skill off` / `/skill clear` — manage skill selection
- `/plan` — show the current investigation plan
- `/memory` — show session memory (URLs, endpoints, cookies, technologies, decoded values, files, flags)
- `/evidence` — show the evidence log (every tool result)
- `/status` — show challenge type, plan progress, evidence, memory, and flag status
- `/specialists` — list specialists and current recommendations
- `/specialists <name>` — run one specialist explicitly (e.g. `/specialists web.sql_injection`)
- `/limits` — show resource usage and limits
- `/tools` — list available tools and OS availability
- `/help` — show help

Sync the skill library and exit:

```bash
python main.py --sync-skills
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## Project Structure

```
CTF-Agent 4.0/
├── main.py                  # CLI entry point (chat loop + /tools + /help + --sync-skills)
├── config.py                # Configuration from env vars (incl. Stage 2-7 vars)
├── agent/
│   ├── __init__.py
│   ├── chat_agent.py        # Agent logic + tool-calling loop + skills + Stage 6 loop + Stage 7 specialists/limits
│   ├── conversation.py      # Conversation history manager
│   ├── planner.py           # Investigation plan generation + step tracking (Stage 6)
│   ├── memory.py            # Session memory: URLs, endpoints, cookies, tech, decoded, files (Stage 6)
│   ├── evidence.py          # Evidence log + structured report (Stage 6)
│   ├── workflow.py          # Challenge type detection + workflows + progress (Stage 6)
│   └── prompts.py           # System prompt with CTF-player rules + skill/plan/specialist placeholders
├── providers/
│   ├── __init__.py
│   ├── base_provider.py     # Abstract base + error classes + tool support
│   ├── openrouter_provider.py  # OpenRouter adapter + tool-call parsing
│   └── opencode_provider.py    # OpenCode adapter + tool-call parsing
├── specialists/             # Stage 7: specialist framework
│   ├── __init__.py
│   ├── base.py              # SpecialistResult + Specialist base + evidence view (spec 15)
│   ├── limits.py            # Resource limits: HTTP/commands/specialists/duplicates/timeouts (spec 16)
│   ├── router.py            # Specialist selection router (spec 13)
│   ├── web/                 # 11 web specialists (SQLi, auth, JWT, SSTI, LFI, JS/API, upload, GraphQL, WS, race, PHP)
│   └── binary/              # 6 binary specialists (triage, buffer overflow, format string, ret2win, ROP, pwntools)
├── tools/
│   ├── __init__.py
│   ├── registry.py          # Tool registry, metadata, validation, results
│   ├── workspace.py         # Centralized workspace path security
│   ├── file_tools.py        # list_files, read_text_file, inspect_file, search_files, calculate_file_hash
│   ├── data_tools.py        # decode_data (original, kept intact)
│   ├── decoder_tools.py     # Extended decoders: octal, decimal, ASCII, UTF-8, JWT, Gzip, Zlib (Stage 5)
│   ├── command_tools.py     # run_ctf_command (allowlist + validation)
│   ├── http_security.py     # URL safety validation (Stage 3)
│   ├── http_session.py      # Persistent HTTP session + masking (Stage 3)
│   ├── html_parser.py       # HTML extraction helpers (Stage 3)
│   ├── http_tools.py        # http_request, inspect_webpage, etc. (Stage 3)
│   ├── web_tools.py         # GET/POST/PUT/DELETE, headers, robots/sitemap, discovery (Stage 5)
│   ├── binary_tools.py      # file/strings/readelf/objdump/nm/ldd/xxd/hexdump/checksec (Stage 5)
│   ├── recon_tools.py       # login/admin finders, tech detection, email/version extraction (Stage 5)
│   ├── js_analysis.py       # JS download/beautify/search + endpoint/secret/GraphQL/WS extraction (Stage 7)
│   ├── binary_pwn.py        # cyclic, pack/unpack, crash-offset, ret2win, GOT/PLT, gadgets (Stage 7)
│   ├── pwn_session.py       # Optional pwntools session manager (local process / user-provided remote) (Stage 7)
│   ├── skill_loader.py      # Skill file loader + minimal YAML front matter (Stage 4)
│   ├── skill_registry.py    # Skill registry, duplicates, categories (Stage 4)
│   ├── skill_router.py      # Deterministic skill scoring + selection (Stage 4)
│   ├── skill_sync.py        # Git-based skill sync (Stage 4)
│   └── retry.py             # Transient-failure retry logic (Stage 6)
├── skills/                  # Bundled skill library (46 skills: 5 common, 24 web, 17 binary)
│   ├── README.md
│   ├── common/
│   ├── web/
│   └── binary/
├── challenges/              # Authorized challenge workspace
│   └── test/                # Test challenge files
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── fixtures/            # Test fixture files (incl. sample.js for Stage 7)
│   ├── test_config.py
│   ├── test_providers.py
│   ├── test_workspace.py
│   ├── test_file_tools.py
│   ├── test_data_tools.py
│   ├── test_command_tools.py
│   ├── test_registry.py
│   ├── test_tools_integration.py
│   ├── test_http_security.py
│   ├── test_http_session.py
│   ├── test_http_tools.py
│   ├── test_html_parser.py
│   ├── test_skill_loader.py
│   ├── test_skill_registry.py
│   ├── test_skill_router.py
│   ├── test_skill_sync.py
│   ├── test_skill_agent_integration.py
│   ├── test_decoder_tools.py
│   ├── test_web_tools.py
│   ├── test_binary_tools.py
│   ├── test_recon_tools.py
│   ├── test_stage5_integration.py
│   ├── test_retry.py
│   ├── test_memory.py
│   ├── test_evidence.py
│   ├── test_workflow.py
│   ├── test_planner.py
│   ├── test_stage6_agent_integration.py
│   ├── test_stage7_specialists.py
│   ├── test_stage7_router.py
│   ├── test_stage7_limits.py
│   ├── test_stage7_js_analysis.py
│   ├── test_stage7_binary_pwn.py
│   └── test_stage7_integration.py
├── .env.example
├── requirements.txt
└── README.md
```

## Security Notes

- All file operations are confined to the `CTF_WORKSPACE` directory (default `challenges/`).
- Path traversal (`..`), absolute system paths, environment files, and system directories are blocked.
- `run_ctf_command` uses `shell=False`, an allowlist, shell operator blocking, argument validation, timeouts, and output truncation.
- All HTTP requests go through URL safety validation (scheme, credentials, localhost/private/metadata IPs, redirects, ports).
- Sensitive cookies and headers (session, auth, token, etc.) are masked in tool output.
- Web discovery tools use small conservative built-in wordlists; no brute-force scanning.
- Binary helper commands run with `shell=False` and report friendly errors when unavailable.
- JWT decoding never verifies signatures and never trusts token content; it is a decoder only.
- Stage 7 specialists are analysis modules: they inspect evidence and recommend low-risk steps; they never execute destructive actions.
- SQL injection specialists never recommend DROP/DELETE/UPDATE/INSERT, file-writing SQL, or OS command execution (spec 2).
- Crash/offset analysis runs only on executable files inside the challenge workspace with short timeouts; unrelated system programs are never run.
- pwntools remote sessions connect only to user-provided authorized CTF hosts/ports; metadata, loopback (by default), and private addresses follow the same policy as the HTTP tools.
- JavaScript analysis output is capped to relevant matches; scripts are never dumped wholesale.
- Resource limits (HTTP requests, commands, specialist calls, duplicates, global timeout) stop the loop and return the strongest confirmed evidence.
- The agent must not reveal API keys, environment variables, or internal secrets.
- Flags are only reported when the exact value is observed in verified tool output.
- Skills are operational hints only — they are never evidence and cannot override safety rules.
- Stage 6 evidence log records only tool results; confirmed findings are derived exclusively from successful tool outputs.
- Session memory stores cookie *names* only — cookie values are never persisted.
- Retry logic only retries transient failures (timeouts, network/5xx errors); permanent validation and security errors are never retried.
- Retries re-run the same tool with the same arguments, so they are safe for read-only analysis tools; state-changing tools still pass through the same URL/workspace security checks on every attempt.
- The autonomous planner and workflow recommendations are guidance only; they never bypass URL validation, workspace confinement, or command allowlists.
