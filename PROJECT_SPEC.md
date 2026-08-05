# CTF Expert AI Agent — Project Specification

## 1. Project Goal

Create a command-line AI agent that specializes in solving authorized Capture the Flag challenges, especially:

* Web exploitation
* Binary exploitation
* Reverse engineering tasks related to binary challenges
* Supporting tasks such as decoding, file inspection, source-code analysis, database inspection, HTTP testing, and vulnerability research

The agent should behave like an experienced CTF security engineer. It must reason step by step internally, use appropriate skills and tools, inspect evidence, test possible solutions, and continue until it either confirms a flag or explains what remains unresolved.

The agent must only be used for authorized CTF challenges, training platforms, lab environments, and systems where the user has permission.

---

## 2. Main User Workflow

The user will provide information such as:

* Challenge name
* Challenge category
* Difficulty
* Challenge description
* Target URL, when applicable
* Local challenge files, when applicable
* Additional hints or credentials, when applicable

Example input:

Challenge name: No FA
Category: Web Exploitation
Difficulty: Medium
Description: Inspect the provided source code and leaked database, determine the authentication method, access the website, and retrieve the flag.
Target: http://example-ctf.local:5000
Files: challenges/no-fa/

The agent should then:

1. Understand and classify the challenge.
2. Inspect the available local files.
3. Search the installed skill library for relevant skills.
4. Select only the skills that apply to the current challenge.
5. Create an investigation plan.
6. Use tools to collect evidence.
7. Test possible vulnerabilities or solutions.
8. Keep track of confirmed findings and unsuccessful attempts.
9. Continue until the flag is confirmed or meaningful progress stops.
10. Return the final confirmed flag and concise supporting evidence.

---

## 3. Expected Agent Identity

The agent should identify itself as:

“A CTF security engineering assistant specializing in web exploitation and binary exploitation.”

The agent should:

* Be systematic rather than guessing.
* Inspect evidence before making conclusions.
* Use tools whenever results can be verified.
* Avoid repeatedly attempting the same failed action.
* Adapt its strategy when an approach fails.
* Separate confirmed facts from hypotheses.
* Prefer the simplest likely vulnerability first.
* Record important discoveries during the current session.
* Ask the user only when information is genuinely unavailable.
* Continue normal conversation when the user is not submitting a challenge.

The agent should not claim that it has found a flag unless the exact flag value appears in a verified tool result, file, program output, HTTP response, debugger output, or another reliable challenge source.

---

## 4. Normal Conversation Mode

The agent must support normal conversation in addition to challenge-solving mode.

It should be able to:

* Explain CTF concepts.
* Discuss possible approaches.
* Help the user prepare a challenge folder.
* Explain tool output.
* Recommend the next debugging step.
* Answer questions about the agent itself.
* Enter challenge-solving mode when sufficient challenge information is provided.

The program must not assume that every message is a request to solve a challenge.

---

## 5. Challenge Workspace

The project should contain a dedicated challenge directory.

Recommended structure:

ctf-agent/
├── main.py
├── config.py
├── agent/
│   ├── prompts.py
│   ├── orchestrator.py
│   ├── state.py
│   └── memory_manager.py
├── tools/
│   ├── file_tools.py
│   ├── data_tools.py
│   ├── http_tools.py
│   ├── web_tools.py
│   ├── database_tools.py
│   ├── binary_tools.py
│   ├── command_tools.py
│   └── account_tools.py
├── skills/
├── memory/
│   ├── verified_patterns.json
│   └── session_logs/
├── challenges/
│   └── challenge-name/
│       ├── challenge.json
│       ├── files/
│       └── notes/
├── tests/
├── .env
├── requirements.txt
└── README.md

All challenge files should be stored inside:

challenges/<challenge-name>/files/

The agent must be able to:

* List challenge files recursively.
* Read text files.
* Detect binary files.
* Inspect file metadata.
* Read Python, JavaScript, PHP, C, HTML, configuration, log, and source-code files.
* Inspect SQLite databases.
* Extract readable strings from binaries.
* Calculate file hashes.
* Inspect archive contents.
* Decode common encodings.
* Save temporary outputs inside the challenge folder.
* Prevent challenge tools from accessing unrelated sensitive system locations.

---

## 6. Challenge Metadata

Each challenge may have a `challenge.json` file.

Example:

{
"name": "No FA",
"category": "web",
"difficulty": "medium",
"description": "Determine the authentication mechanism and retrieve the flag.",
"target_url": "http://example-ctf.local:5000",
"authorized": true,
"files_directory": "files"
}

The agent should read this metadata before beginning an investigation.

If `authorized` is not true, the agent should ask the user to confirm that the target is an authorized CTF or lab environment before performing active exploitation.

---

## 7. Core File Tools

The first tool group should include:

* `list_files`
* `read_text_file`
* `inspect_file`
* `inspect_binary`
* `calculate_hash`
* `extract_archive`
* `search_files`
* `write_note`
* `read_challenge_metadata`

These tools should:

* Use safe paths relative to the project workspace.
* Limit excessively large outputs.
* Detect null bytes before reading a file as text.
* Clearly report tool errors.
* Never silently fail.
* Return structured results when possible.

---

## 8. Data and Database Tools

The agent should support:

* Base64 decoding
* Hex decoding
* URL decoding
* JWT inspection
* Hash identification
* Compression detection
* SQLite database inspection
* Listing database tables
* Viewing table schemas
* Running read-only SQL queries
* Extracting metadata from structured files
* Reading JSON, CSV, and XML

Database access should be read-only by default.

The agent must not automatically modify challenge databases unless modification is clearly required, authorized, and performed on a temporary copy.

---

## 9. Web and HTTP Tools

The agent should be able to:

* Send GET, POST, PUT, PATCH, DELETE, HEAD, and OPTIONS requests.
* Set query parameters.
* Send form data.
* Send JSON bodies.
* Set custom headers.
* Manage cookies.
* Maintain an HTTP session.
* Follow or disable redirects.
* Inspect response headers.
* Save response bodies.
* Parse HTML forms.
* Extract links, scripts, comments, and endpoints.
* Inspect JavaScript files.
* Test authentication flows.
* Submit login and registration forms.
* Upload files when required by an authorized challenge.
* Work with CSRF tokens.
* Handle session cookies.
* Compare authenticated and unauthenticated responses.

The tool should support a persistent session so that registration, login, and later authenticated requests use the same cookies.

The agent may create a temporary account only when:

* The target is an authorized CTF or lab.
* Registration is part of the intended challenge workflow.
* The account uses generated, non-personal information.
* The credentials are stored only inside the active challenge workspace.
* The tool does not attempt to bypass CAPTCHA, email verification, phone verification, or third-party identity checks.

Suggested generated credentials:

* Username: `ctfplayer_<random>`
* Email: a challenge-provided address or a safe placeholder accepted by the challenge
* Password: randomly generated and saved in the challenge session file

---

## 10. Web Exploitation Capabilities

Relevant web challenge support should include:

* Source-code review
* Authentication logic analysis
* Session and cookie inspection
* SQL injection testing
* NoSQL injection testing
* Command injection testing
* Path traversal testing
* Local file inclusion testing
* Server-side template injection testing
* Insecure direct object reference testing
* Access-control testing
* File-upload analysis
* JWT weakness analysis
* Client-side JavaScript analysis
* API endpoint discovery
* Parameter manipulation
* HTTP method testing
* Header-based behavior testing
* Race-condition investigation where appropriate

The agent must use evidence-driven testing and avoid sending large, uncontrolled payload sets.

---

## 11. Binary Exploitation Capabilities

Binary-related tools should support commands such as:

* `file`
* `strings`
* `checksec`
* `readelf`
* `objdump`
* `nm`
* `ldd`
* `xxd`
* `hexdump`
* `gdb`
* `python`
* `python3`

Optional support may later include:

* GDB with pwndbg or GEF
* pwntools
* ROPgadget
* one_gadget
* radare2
* Ghidra integration
* angr

The initial version should focus on safe inspection before advanced automation.

The agent should be able to:

* Identify architecture and endianness.
* Review security protections.
* Inspect symbols and imports.
* Find interesting strings.
* Disassemble selected functions.
* Run the binary with controlled input.
* Detect crashes and record exit codes.
* Generate cyclic patterns.
* Determine overwrite offsets.
* Build and test local proof-of-concept exploits.
* Connect to remote CTF services when provided.
* Capture and verify the final flag.

Commands must be restricted by an allowlist. Dangerous shell features, unrestricted command chaining, destructive file operations, and access outside the workspace should be blocked.

---

## 12. Skill System

Skills will be stored in a GitHub repository provided by the user.

The agent should support:

* Cloning the configured skill repository.
* Updating the local copy manually or through an explicit sync command.
* Reading skill metadata.
* Searching skill names, descriptions, tags, and content.
* Selecting relevant skills based on challenge category and evidence.
* Loading only a small number of relevant skills into the model context.
* Reporting which skills were selected and why.
* Continuing without a skill when no suitable skill exists.

Recommended skill metadata:

---

name: SQL Injection
category: web
tags:

* sql
* authentication
* database
  difficulty:
* easy
* medium
* hard
  triggers:
* login form
* SQL query
* SQLite
* database error

---

A skill should contain:

* When to use it
* Initial checks
* Investigation steps
* Useful tools
* Common failure patterns
* Success criteria
* When to stop using the skill
* Related skills

Skills should guide the agent but should not be treated as guaranteed solutions.

The skill loader should not load the entire repository into every request because this will increase response time and confuse the model.

---

## 13. Engineering and Efficiency Skills

In addition to exploitation skills, the skill repository may contain engineering skills such as:

* Systematic debugging
* Evidence tracking
* Hypothesis testing
* Tool-output summarization
* Context compression
* Failure recovery
* Root-cause analysis
* Search strategy
* Task decomposition
* Time-aware investigation
* Avoiding repeated attempts
* Minimal reproducible testing
* Logging and checkpointing

These skills should improve the agent’s workflow rather than directly exploit a target.

---

## 14. Agent Investigation State

For every challenge, maintain structured state containing:

* Challenge information
* Selected skills
* Confirmed findings
* Current hypotheses
* Attempted actions
* Failed attempts
* Files inspected
* URLs tested
* Credentials created for the challenge
* Possible flag candidates
* Final confirmed flag
* Recommended next actions

This state should prevent the agent from forgetting earlier evidence or repeating identical attempts.

Suggested statuses:

* `not_started`
* `investigating`
* `possible_solution`
* `flag_confirmed`
* `blocked`
* `user_stopped`

---

## 15. Verified Memory System

The agent should create long-term memory only after a challenge has been solved and the flag has been confirmed.

It must not store every conversation or failed guess as permanent knowledge.

A verified memory entry should contain:

* Challenge category
* Difficulty
* Vulnerability type
* Important indicators
* Successful investigation sequence
* Tools that produced useful evidence
* Failed approaches worth avoiding
* General lesson
* Date solved
* Confirmation that a flag was found

The actual flag should normally not be used as reusable knowledge because flags are challenge-specific.

Example memory entry:

{
"category": "web",
"difficulty": "medium",
"vulnerability": "weak session token generated from user ID",
"indicators": [
"session cookie changed predictably between accounts",
"source code used direct numeric user ID"
],
"successful_steps": [
"read authentication source",
"compare cookies from two accounts",
"modify user ID inside session token",
"request admin endpoint"
],
"failed_steps": [
"basic SQL injection payloads"
],
"lesson": "Inspect session generation before brute-forcing login forms.",
"verified": true
}

Before saving memory, remove:

* Passwords
* API keys
* Session cookies
* Personal information
* Target-specific secrets
* Unnecessary raw outputs

Memory should be retrieved by similarity to the current challenge, but the agent should treat it as guidance rather than proof.

---

## 16. Progress and Time Management

The first versions should not force-stop the model using a strict time limit.

Instead, the agent should track:

* Elapsed time
* Number of agent steps
* Number of tool calls
* Number of repeated failures
* Whether new evidence has been found recently

At configurable thresholds, display a warning such as:

“Progress alert: The challenge has not been solved after 20 steps. The agent estimates that additional investigation is needed.”

The program should then offer the user choices:

1. Continue for another investigation block.
2. Show current findings.
3. Change strategy.
4. Stop the challenge.

The alert must not automatically terminate the process unless the user selected a strict limit in the configuration.

The agent should save a checkpoint before pausing.

---

## 17. Model Provider Configuration

The system should support OpenRouter and OpenCode through configurable provider adapters.

Environment variables may include:

* `LLM_PROVIDER`
* `OPENROUTER_API_KEY`
* `OPENROUTER_MODEL`
* `OPENCODE_API_KEY`
* `OPENCODE_MODEL`
* `MODEL_TIMEOUT`
* `MAX_AGENT_STEPS`
* `PROGRESS_ALERT_STEPS`

The initial preferred model is Ling 3.0 or another available free model.

The code should not hard-code one provider throughout the application. Provider-specific code should be isolated so that models can be changed without rewriting the entire agent.

The program should clearly distinguish:

* Invalid API key
* Unsupported model
* Provider outage
* Rate limit
* Payment-required error
* Request timeout
* Empty model output
* Tool execution error

A provider failure should not be reported as a CTF-solving failure.

---

## 18. Final Answer Format

When a flag is confirmed:

FLAG: flag{confirmed_value}

Evidence:

* Brief explanation of where the flag was found.
* Important vulnerability or solution path.
* Tool result that confirmed it.

When no flag is confirmed:

STATUS: No confirmed flag yet.

Confirmed findings:

* Finding 1
* Finding 2

Current blocker:

* Explanation

Best next action:

* Specific next step

The agent must never invent a flag or return an unverified candidate as confirmed.

---

## 19. Logging

Each challenge should have a session log containing:

* User inputs
* Agent decisions
* Tool names and arguments, with secrets redacted
* Tool results, truncated when necessary
* Errors
* Selected skills
* Checkpoints
* Final result

Logs should make debugging possible without exposing API keys, passwords, cookies, or sensitive tokens.

---

## 20. Development Requirements

The project must be developed incrementally.

Pi must not rewrite the whole project when fixing a small bug.

For every requested change, Pi should:

1. Inspect the existing project.
2. Explain the likely cause of the issue.
3. Identify the files that need to change.
4. Make the smallest reasonable change.
5. Preserve working functionality.
6. Run relevant tests.
7. Report changed files.
8. Report test results.
9. Mention remaining limitations.

Every major module should have independent tests.

The agent should not advance to the next development stage until the current stage passes its acceptance tests.
