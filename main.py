#!/usr/bin/env python3
"""CTF Agent - Stage 1+2+3+4+5+6: Conversational AI with local challenge analysis,
controlled HTTP tools, a modular skill system, and autonomous reasoning for
authorized CTF challenges.

A command-line chat loop with conversation history, provider adapters,
a modular tool system, safe web inspection tools, skill routing, and an
autonomous investigation planner with evidence logging.
"""

import argparse
import os
import sys

# Ensure project root is on the path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import Config
from agent.chat_agent import ChatAgent
from tools.registry import ToolRegistry
from tools.file_tools import (
    calculate_file_hash,
    inspect_file,
    list_files,
    read_text_file,
    search_files,
)
from tools.data_tools import decode_data
from tools.decoder_tools import decode_data as decode_data_extended
from tools.command_tools import run_ctf_command
from tools.http_tools import (
    compare_http_responses,
    extract_web_elements,
    http_request,
    init_http_session_from_config,
    inspect_webpage,
    manage_http_session,
)
from tools.web_tools import (
    analyze_headers,
    discover_api_endpoints,
    discover_hidden_endpoints,
    enumerate_directories,
    extract_forms_from_page,
    extract_html_comments,
    extract_javascript_from_page,
    extract_links_from_page,
    http_delete,
    http_get,
    http_post,
    http_put,
    manage_cookies,
    read_robots_txt,
    read_sitemap_xml,
)
from tools.binary_tools import (
    analyze_binary,
    binary_checksec,
    binary_file_info,
    binary_hexdump,
    binary_libraries,
    binary_objdump,
    binary_readelf,
    binary_strings,
    binary_symbols,
)
from tools.recon_tools import (
    detect_framework,
    detect_server,
    detect_technology_stack,
    extract_emails,
    extract_version_info,
    find_admin_page,
    find_api_endpoints,
    find_backup_files,
    find_login_page,
)
from tools.js_analysis import (
    analyze_javascript_file,
    analyze_javascript_text,
    analyze_javascript_url,
    beautify_javascript,
    search_javascript_file,
    search_javascript_text,
)
from tools.binary_pwn import (
    pwn_analyze_ret2win,
    pwn_crash_analyze,
    pwn_cyclic,
    pwn_cyclic_find,
    pwn_elf_info,
    pwn_find_gadgets,
    pwn_find_win_function,
    pwn_format_string_analysis,
    pwn_got_plt,
    pwn_pack,
    pwn_unpack,
    pwn_verify_offset,
)
from tools.pwn_session import (
    init_pwn_session_from_config,
    pwntools_status,
    session_manager as pwn_session_manager,
)
from tools.http_session import session_manager


HELP_TEXT = """
CTF Agent - Stage 1+2+3+4+5+6+7: AI + Tools + Skills + Autonomous + Specialists

Commands:
  /exit          Quit the agent
  /reset         Clear conversation history, memory, evidence, plan, limits
  /model         Set the model name (e.g. /model ling-3.0)
  /provider      Set the provider (openrouter or opencode)
  /session       Show a safe summary of the current HTTP session
  /skills        List the loaded skill library by category
  /skill <id>    Manually activate a skill by identifier
  /skill auto    Enable automatic skill selection
  /skill off     Disable skill usage
  /skill clear   Clear manual skill selections
  /plan          Show the current investigation plan
  /memory        Show session memory (URLs, endpoints, cookies, technologies)
  /evidence      Show the evidence log (every tool result)
  /status        Show challenge type, progress, and flag status
  /specialists   List specialists and current recommendations
  /specialists <name>  Run one specialist explicitly (e.g. /specialists web.sql_injection)
  /limits        Show resource usage and limits
  /help          Show this help message
  /tools         List available analysis tools

Any other input is sent as a normal chat message.

The agent can analyze files inside the configured challenge workspace
(default: challenges/) and inspect authorized CTF web challenges with
safe HTTP tools. Relevant skills are auto-selected and injected into
context as operational guidance (never as evidence).

Stage 5 adds:
  - Web tools: GET/POST/PUT/DELETE wrappers, cookie management, header
    analysis, robots.txt/sitemap.xml readers, HTML link/form/JS/comment
    extraction, directory enumeration, API and hidden endpoint discovery.
  - Binary tools: file, strings, readelf, objdump, nm, ldd, xxd, hexdump
    (and checksec when installed) with friendly errors if unavailable.
  - Decoders: Base64, hex, URL, ROT13, binary, octal, decimal, ASCII,
    UTF-8, JWT, Gzip, Zlib, and auto-detection.
  - Recon tools: login/admin finders, API/backup discovery, tech stack
    detection, email and version extraction.

Stage 6 adds:
  - Autonomous investigation: a planner generates steps before tool use.
  - Automatic tool selection per challenge type (Web/Binary/Crypto/
    Forensics/Misc) and evidence.
  - Retry logic for transient tool failures (timeouts, network errors).
  - Session memory for URLs, cookies, endpoints, technologies, decoded
    values, files, and flags.
  - An evidence log; every reported finding comes from tool output.
  - Structured final responses: Confirmed Findings / Evidence / Flag
    Status / Recommended Next Step.

Stage 7 adds:
  - Specialist workflows (web + binary) with structured results.
  - A specialist router that selects specialists from evidence.
  - JavaScript analysis: endpoint/secret/GraphQL/WebSocket extraction,
    source-map references, hidden routes, client-side authz, beautifier.
  - Binary exploitation helpers: cyclic patterns, packing, crash-offset
    analysis, ret2win planning, GOT/PLT, ROP gadgets (pure Python).
  - Optional pwntools integration for local/remote challenge sessions.
  - Resource limits: max HTTP requests, command executions, specialist
    calls, duplicate-action detection, global challenge timeout.
"""


def _build_tool_registry(config: Config) -> ToolRegistry:
    """Create and populate the tool registry."""
    registry = ToolRegistry()

    registry.register(
        name="list_files",
        func=list_files,
        description=(
            "Recursively list challenge files inside the workspace "
            "with relative paths and file sizes. "
            "Ignores .git, .venv, __pycache__, and hidden files."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path within the workspace to list (optional, defaults to workspace root).",
                },
            },
        },
        required=[],
        timeout_seconds=15,
        category="file",
    )

    registry.register(
        name="read_text_file",
        func=read_text_file,
        description=(
            "Read a text file safely inside the workspace. "
            "Detects binary files and returns a clear message instead."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the text file within the workspace.",
                },
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=15,
        category="file",
    )

    registry.register(
        name="inspect_file",
        func=inspect_file,
        description=(
            "Inspect a file and report metadata including filename, "
            "size, likely type, SHA-256 hash, first bytes, printable strings, "
            "and whether the file is text or binary."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the file within the workspace.",
                },
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=15,
        category="file",
    )

    registry.register(
        name="search_files",
        func=search_files,
        description=(
            "Search text recursively inside the challenge workspace. "
            "Supports plain text or regular expressions."
        ),
        parameters={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "The search term or regular expression.",
                },
                "path": {
                    "type": "string",
                    "description": "Relative path within the workspace to start searching from (optional).",
                },
                "use_regex": {
                    "type": "boolean",
                    "description": "If true, treat pattern as a regular expression.",
                },
            },
            "required": ["pattern"],
        },
        required=["pattern"],
        timeout_seconds=30,
        category="file",
    )

    registry.register(
        name="calculate_file_hash",
        func=calculate_file_hash,
        description=(
            "Calculate a cryptographic hash (MD5, SHA-1, SHA-256, or SHA-512) "
            "of a file inside the workspace."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the file within the workspace.",
                },
                "algorithm": {
                    "type": "string",
                    "description": "Hash algorithm: md5, sha1, sha256, or sha512.",
                    "enum": ["md5", "sha1", "sha256", "sha512"],
                },
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=15,
        category="file",
    )

    registry.register(
        name="decode_data",
        func=decode_data_extended,
        description=(
            "Decode data from Base64, hexadecimal, URL encoding, ROT13, "
            "binary, octal, decimal, ASCII, UTF-8, JWT, Gzip, or Zlib. "
            "Use 'auto' for automatic detection."
        ),
        parameters={
            "type": "object",
            "properties": {
                "data": {
                    "type": "string",
                    "description": "The encoded string to decode.",
                },
                "encoding": {
                    "type": "string",
                    "description": "Encoding: base64, hex, url, rot13, binary, octal, decimal, ascii, utf8, jwt, gzip, zlib, or auto.",
                    "enum": ["base64", "hex", "url", "rot13", "binary", "octal", "decimal", "ascii", "utf8", "jwt", "gzip", "zlib", "auto"],
                },
            },
            "required": ["data"],
        },
        required=["data"],
        timeout_seconds=10,
        category="data",
    )

    registry.register(
        name="run_ctf_command",
        func=run_ctf_command,
        description=(
            "Run an approved local analysis command inside the workspace. "
            "Allowed commands: file, strings, xxd, hexdump, readelf, objdump, "
            "nm, ldd, grep, rg, python, python3. "
            "Shell operators and dangerous arguments are blocked."
        ),
        parameters={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The command to run (e.g. 'strings challenges/test/sample.bin').",
                },
            },
            "required": ["command"],
        },
        required=["command"],
        timeout_seconds=30,
        category="command",
    )

    registry.register(
        name="http_request",
        func=http_request,
        description=(
            "Send a controlled HTTP request to an authorized CTF target. "
            "Methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS. "
            "Supports query params, headers, form data, JSON/raw bodies, "
            "cookies, redirect control, and timeout. Returns status, headers, "
            "cookies, redirect history, truncated body, and elapsed time. "
            "Only http/https targets are allowed; localhost/private/metadata "
            "addresses are blocked by default."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL (http/https only)."},
                "method": {"type": "string", "description": "HTTP method (default GET).", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]},
                "params": {"type": "object", "description": "Query parameters."},
                "headers": {"type": "object", "description": "Request headers."},
                "form_data": {"type": "object", "description": "Form-encoded body."},
                "json_body": {"type": "object", "description": "JSON body."},
                "raw_body": {"type": "string", "description": "Raw text body."},
                "cookies": {"type": "object", "description": "Cookies to send."},
                "follow_redirects": {"type": "boolean", "description": "Follow redirects (default false)."},
                "timeout": {"type": "number", "description": "Timeout in seconds (default from config)."},
            },
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="inspect_webpage",
        func=inspect_webpage,
        description=(
            "Inspect an authorized web page: title, status, content type, "
            "detected technologies (heuristic), server header, forms, scripts, "
            "stylesheets, comments, meta tags, visible text summary, possible "
            "API routes, security headers, and cookies."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL (http/https only)."},
            },
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="extract_web_elements",
        func=extract_web_elements,
        description=(
            "Extract elements from a web page: links, forms (actions, methods, "
            "inputs, hidden fields), scripts, comments, iframes, buttons. "
            "Optional element_type filter."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL (http/https only)."},
                "element_type": {"type": "string", "description": "Filter: links, forms, inputs, hidden_inputs, scripts, stylesheets, comments, meta, buttons, iframes, or all."},
            },
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="compare_http_responses",
        func=compare_http_responses,
        description=(
            "Compare two HTTP responses (URLs or stored JSON response dicts): "
            "status, body length, headers, cookies, redirects, similarity, "
            "and notable changed lines. Does not print full bodies."
        ),
        parameters={
            "type": "object",
            "properties": {
                "response_a": {"type": "string", "description": "URL or stored JSON response for comparison."},
                "response_b": {"type": "string", "description": "URL or stored JSON response for comparison."},
            },
            "required": ["response_a", "response_b"],
        },
        required=["response_a", "response_b"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="manage_http_session",
        func=manage_http_session,
        description=(
            "Manage the shared HTTP session: show cookies, clear cookies, "
            "set/remove a cookie, reset session, show/set/remove default "
            "headers. Sensitive values are masked in output."
        ),
        parameters={
            "type": "object",
            "properties": {
                "operation": {"type": "string", "description": "show, clear_cookies, set_cookie, remove_cookie, reset, show_headers, set_header, remove_header."},
                "cookie_name": {"type": "string"},
                "cookie_value": {"type": "string"},
                "cookie_domain": {"type": "string"},
                "header_name": {"type": "string"},
                "header_value": {"type": "string"},
            },
            "required": ["operation"],
        },
        required=["operation"],
        timeout_seconds=10,
        category="web",
    )

    # ------------------------------------------------------------------
    # Stage 5: convenience HTTP wrappers
    # ------------------------------------------------------------------
    registry.register(
        name="http_get",
        func=http_get,
        description=(
            "Send a GET request to an authorized CTF target. Returns status, "
            "headers, cookies, redirects, and truncated body."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL."},
                "params": {"type": "object", "description": "Query parameters."},
                "headers": {"type": "object", "description": "Request headers."},
                "cookies": {"type": "object", "description": "Cookies to send."},
                "timeout": {"type": "number"},
                "max_body_chars": {"type": "integer"},
            },
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="http_post",
        func=http_post,
        description=(
            "Send a POST request with form/JSON/raw body support to an "
            "authorized CTF target."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "form_data": {"type": "object", "description": "Form-encoded body."},
                "json_body": {"type": "object", "description": "JSON body."},
                "raw_body": {"type": "string", "description": "Raw body."},
                "headers": {"type": "object"},
                "cookies": {"type": "object"},
                "params": {"type": "object"},
                "timeout": {"type": "number"},
            },
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="http_put",
        func=http_put,
        description=(
            "Send a PUT request (JSON or raw body) to an authorized CTF target."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "json_body": {"type": "object"},
                "raw_body": {"type": "string"},
                "headers": {"type": "object"},
                "cookies": {"type": "object"},
                "timeout": {"type": "number"},
            },
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="http_delete",
        func=http_delete,
        description=(
            "Send a DELETE request to an authorized CTF target."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "headers": {"type": "object"},
            },
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="manage_cookies",
        func=manage_cookies,
        description=(
            "Manage the shared HTTP session's cookies: show, clear_cookies, "
            "set_cookie, remove_cookie. Sensitive values are masked."
        ),
        parameters={
            "type": "object",
            "properties": {
                "operation": {"type": "string", "description": "show, clear_cookies, set_cookie, remove_cookie."},
                "cookie_name": {"type": "string"},
                "cookie_value": {"type": "string"},
                "cookie_domain": {"type": "string"},
            },
            "required": ["operation"],
        },
        required=["operation"],
        timeout_seconds=10,
        category="web",
    )

    registry.register(
        name="analyze_headers",
        func=analyze_headers,
        description=(
            "Fetch a URL and report all response headers plus which security "
            "headers are present or missing."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "max_body_chars": {"type": "integer"},
            },
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="read_robots_txt",
        func=read_robots_txt,
        description=(
            "Fetch /robots.txt from a target and summarize its Allow/Disallow "
            "directives and referenced paths."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="read_sitemap_xml",
        func=read_sitemap_xml,
        description=(
            "Fetch /sitemap.xml and list all URLs it references (handles "
            "sitemap index files too)."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="extract_links_from_page",
        func=extract_links_from_page,
        description=(
            "Extract all links (href/src) from a page, resolved to absolute URLs."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="extract_forms_from_page",
        func=extract_forms_from_page,
        description=(
            "Extract forms from a page: action, method, and all input fields "
            "(including hidden ones)."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="extract_javascript_from_page",
        func=extract_javascript_from_page,
        description=(
            "Extract JavaScript references and inline scripts from a page."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="extract_html_comments",
        func=extract_html_comments,
        description=(
            "Extract HTML comments from a page (often hide hints and endpoints)."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="enumerate_directories",
        func=enumerate_directories,
        description=(
            "Probe a small conservative list of common directory paths on a "
            "target and report non-404 results. No large wordlists."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "wordlist": {"type": "array", "items": {"type": "string"}},
                "max_checks": {"type": "integer"},
            },
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=60,
        category="web",
    )

    registry.register(
        name="discover_api_endpoints",
        func=discover_api_endpoints,
        description=(
            "Discover API endpoints from page source plus a small list of "
            "common API paths."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=60,
        category="web",
    )

    registry.register(
        name="discover_hidden_endpoints",
        func=discover_hidden_endpoints,
        description=(
            "Discover hidden endpoints and sensitive files (.git, .env, "
            "backups, debug logs) from page hints plus a small probe list."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=60,
        category="web",
    )

    # ------------------------------------------------------------------
    # Stage 5: binary analysis tools
    # ------------------------------------------------------------------
    registry.register(
        name="binary_file_info",
        func=binary_file_info,
        description=(
            "Identify a binary's file type and architecture using 'file'. "
            "Returns a friendly error if the command is unavailable."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path inside the workspace."},
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=30,
        category="binary",
    )

    registry.register(
        name="binary_strings",
        func=binary_strings,
        description=(
            "Extract readable strings from a binary ('strings -n <min_length>')."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "min_length": {"type": "integer", "description": "Minimum string length (default 4)."},
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=30,
        category="binary",
    )

    registry.register(
        name="binary_readelf",
        func=binary_readelf,
        description=(
            "Inspect ELF headers/sections (readelf). Section: headers, program, "
            "sections, relocations, or dynamic."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "section": {"type": "string", "description": "headers, program, sections, relocations, dynamic."},
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=30,
        category="binary",
    )

    registry.register(
        name="binary_objdump",
        func=binary_objdump,
        description=(
            "Inspect an object file with objdump: format+headers, or "
            "disassembly with disassemble=true."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "disassemble": {"type": "boolean"},
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=30,
        category="binary",
    )

    registry.register(
        name="binary_symbols",
        func=binary_symbols,
        description=(
            "List symbols in a binary (nm, falls back to objdump -t)."
        ),
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=30,
        category="binary",
    )

    registry.register(
        name="binary_libraries",
        func=binary_libraries,
        description=(
            "List linked shared libraries (ldd)."
        ),
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=30,
        category="binary",
    )

    registry.register(
        name="binary_hexdump",
        func=binary_hexdump,
        description=(
            "Hex dump the first N bytes of a file (xxd or hexdump -C)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "length": {"type": "integer", "description": "Bytes to dump (default 256)."},
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=30,
        category="binary",
    )

    registry.register(
        name="binary_checksec",
        func=binary_checksec,
        description=(
            "Check binary security mitigations with checksec (if installed). "
            "Returns a friendly message if checksec is unavailable."
        ),
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=30,
        category="binary",
    )

    registry.register(
        name="analyze_binary",
        func=analyze_binary,
        description=(
            "Run the full binary analysis workflow: file, checksec (if "
            "installed), strings, readelf, objdump, symbols, interesting "
            "strings, and possible vulnerability notes."
        ),
        parameters={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=90,
        category="binary",
    )

    # ------------------------------------------------------------------
    # Stage 5: recon tools
    # ------------------------------------------------------------------
    registry.register(
        name="find_login_page",
        func=find_login_page,
        description=(
            "Probe common login paths on a target and report which exist."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=60,
        category="web",
    )

    registry.register(
        name="find_admin_page",
        func=find_admin_page,
        description=(
            "Probe common admin paths on a target and report which exist."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=60,
        category="web",
    )

    registry.register(
        name="find_api_endpoints",
        func=find_api_endpoints,
        description=(
            "Probe common API endpoints and report which respond (non-404)."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=60,
        category="web",
    )

    registry.register(
        name="find_backup_files",
        func=find_backup_files,
        description=(
            "Probe for backup files (.bak, .old, .zip, .sql, etc.) on a target."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=60,
        category="web",
    )

    registry.register(
        name="detect_framework",
        func=detect_framework,
        description=(
            "Detect the web framework from page source markers and headers."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="detect_server",
        func=detect_server,
        description=(
            "Report the server software from response headers."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="detect_technology_stack",
        func=detect_technology_stack,
        description=(
            "Combine server + framework + frontend library detection into a "
            "technology stack summary."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="extract_emails",
        func=extract_emails,
        description=(
            "Extract email addresses from a page body."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="extract_version_info",
        func=extract_version_info,
        description=(
            "Extract version numbers from headers and page source."
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    # ------------------------------------------------------------------
    # Stage 7: JavaScript analysis tools (spec 6)
    # ------------------------------------------------------------------

    registry.register(
        name="analyze_javascript_url",
        func=analyze_javascript_url,
        description=(
            "Fetch a JavaScript file from an authorized target and analyze it "
            "for endpoints, API base URLs, secrets/tokens, source maps, "
            "fetch/XHR calls, GraphQL endpoints, WebSocket URLs, hidden routes, "
            "client-side authorization logic, and hardcoded credentials."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL of the JavaScript file (must pass the standard URL safety checks).",
                },
            },
            "required": ["url"],
        },
        required=["url"],
        timeout_seconds=30,
        category="web",
    )

    registry.register(
        name="analyze_javascript_file",
        func=analyze_javascript_file,
        description=(
            "Analyze a JavaScript file inside the workspace for endpoints, "
            "secrets, source maps, GraphQL/WebSocket URLs, and credentials."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the JavaScript file within the workspace.",
                },
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=15,
        category="web",
    )

    registry.register(
        name="analyze_javascript_text",
        func=analyze_javascript_text,
        description=(
            "Analyze JavaScript source passed directly as text (for pasted "
            "snippets) and return a capped findings report."
        ),
        parameters={
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "JavaScript source text to analyze.",
                },
            },
            "required": ["text"],
        },
        required=["text"],
        timeout_seconds=15,
        category="web",
    )

    registry.register(
        name="search_javascript_file",
        func=search_javascript_file,
        description=(
            "Search a JavaScript file inside the workspace for a regex pattern "
            "and return matches with line context."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the JavaScript file.",
                },
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for.",
                },
            },
            "required": ["path", "pattern"],
        },
        required=["path", "pattern"],
        timeout_seconds=15,
        category="web",
    )

    registry.register(
        name="beautify_javascript",
        func=beautify_javascript,
        description=(
            "Beautify minified JavaScript text (one statement per line with "
            "indentation) to make it searchable."
        ),
        parameters={
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Minified JavaScript source.",
                },
            },
            "required": ["text"],
        },
        required=["text"],
        timeout_seconds=15,
        category="web",
    )

    registry.register(
        name="search_javascript_text",
        func=search_javascript_text,
        description=(
            "Search JavaScript source text for a regex pattern with line context."
        ),
        parameters={
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "JavaScript source text.",
                },
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for.",
                },
            },
            "required": ["text", "pattern"],
        },
        required=["text", "pattern"],
        timeout_seconds=15,
        category="web",
    )

    # ------------------------------------------------------------------
    # Stage 7: binary exploitation helpers (specs 9-12)
    # ------------------------------------------------------------------

    registry.register(
        name="pwn_cyclic",
        func=pwn_cyclic,
        description=(
            "Generate a De Bruijn-style cyclic pattern of N characters for "
            "buffer-overflow offset discovery (pure Python, no pwntools needed)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "length": {
                    "type": "integer",
                    "description": "Pattern length (default 64).",
                },
            },
            "required": [],
        },
        required=[],
        timeout_seconds=5,
        category="binary",
    )

    registry.register(
        name="pwn_cyclic_find",
        func=pwn_cyclic_find,
        description=(
            "Find the offset of a substring (>=4 chars) in a cyclic pattern. "
            "Returns -1 when not found."
        ),
        parameters={
            "type": "object",
            "properties": {
                "substring": {
                    "type": "string",
                    "description": "4+ character fragment (e.g. crash bytes).",
                },
            },
            "required": ["substring"],
        },
        required=["substring"],
        timeout_seconds=5,
        category="binary",
    )

    registry.register(
        name="pwn_pack",
        func=pwn_pack,
        description=(
            "Pack an integer into bytes (8/16/32/64-bit, little or big endian). "
            "Returns a hex string representation for payloads."
        ),
        parameters={
            "type": "object",
            "properties": {
                "value": {
                    "type": "integer",
                    "description": "Integer to pack.",
                },
                "bits": {
                    "type": "integer",
                    "description": "Width in bits: 8, 16, 32, or 64.",
                    "enum": [8, 16, 32, 64],
                },
                "endianness": {
                    "type": "string",
                    "description": "little or big.",
                    "enum": ["little", "big"],
                },
            },
            "required": ["value"],
        },
        required=["value"],
        timeout_seconds=5,
        category="binary",
    )

    registry.register(
        name="pwn_unpack",
        func=pwn_unpack,
        description=(
            "Unpack bytes (hex string) into an integer with the given width "
            "and endianness."
        ),
        parameters={
            "type": "object",
            "properties": {
                "data": {
                    "type": "string",
                    "description": "Hex-encoded bytes to unpack.",
                },
                "bits": {
                    "type": "integer",
                    "description": "Width in bits: 8, 16, 32, or 64.",
                    "enum": [8, 16, 32, 64],
                },
                "endianness": {
                    "type": "string",
                    "description": "little or big.",
                    "enum": ["little", "big"],
                },
            },
            "required": ["data"],
        },
        required=["data"],
        timeout_seconds=5,
        category="binary",
    )

    registry.register(
        name="pwn_elf_info",
        func=pwn_elf_info,
        description=(
            "Report file type, architecture, bitness, endianness, linking, "
            "and stripped status for a binary in the workspace."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the binary.",
                },
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=15,
        category="binary",
    )

    registry.register(
        name="pwn_find_win_function",
        func=pwn_find_win_function,
        description=(
            "Search symbols and strings for win/flag-printing functions and "
            "report their addresses (nm/strings)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the binary.",
                },
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=15,
        category="binary",
    )

    registry.register(
        name="pwn_got_plt",
        func=pwn_got_plt,
        description=(
            "Show PLT/GOT relocations (JUMP_SLOT/GLOB_DAT) and dynamic "
            "library entries (readelf)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the binary.",
                },
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=15,
        category="binary",
    )

    registry.register(
        name="pwn_find_gadgets",
        func=pwn_find_gadgets,
        description=(
            "Find simple ROP gadgets (pop rdi; ret, etc.) by scanning objdump "
            "disassembly. Returns confirmed addresses only."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the binary.",
                },
                "gadgets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional gadget list to search for (default: common pop/ret gadgets).",
                },
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=30,
        category="binary",
    )

    registry.register(
        name="pwn_crash_analyze",
        func=pwn_crash_analyze,
        description=(
            "Run a local challenge binary with cyclic input (stdin) and "
            "determine the overwrite offset from the crash. Works only on "
            "files inside the challenge workspace with a timeout."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the executable inside the workspace.",
                },
                "input_length": {
                    "type": "integer",
                    "description": "Cyclic input length (default 512).",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default 10).",
                },
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=20,
        category="binary",
    )

    registry.register(
        name="pwn_verify_offset",
        func=pwn_verify_offset,
        description=(
            "Verify a computed overwrite offset by re-running the local binary "
            "with a marker at that offset and checking the fault address."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the executable.",
                },
                "offset": {
                    "type": "integer",
                    "description": "Offset to verify.",
                },
            },
            "required": ["path", "offset"],
        },
        required=["path", "offset"],
        timeout_seconds=20,
        category="binary",
    )

    registry.register(
        name="pwn_analyze_ret2win",
        func=pwn_analyze_ret2win,
        description=(
            "Combined ret2win analysis: architecture, win function address, "
            "crash offset, and a validated payload plan (nothing invented)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the binary.",
                },
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=40,
        category="binary",
    )

    registry.register(
        name="pwn_format_string_analysis",
        func=pwn_format_string_analysis,
        description=(
            "Static hints for format-string analysis: printf-family symbols "
            "and format-string literals (read-only)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the binary.",
                },
            },
            "required": ["path"],
        },
        required=["path"],
        timeout_seconds=15,
        category="binary",
    )

    # ------------------------------------------------------------------
    # Stage 7: optional pwntools session tools (spec 9)
    # ------------------------------------------------------------------

    registry.register(
        name="pwn_session_start",
        func=_pwn_session_start,
        description=(
            "Start a pwntools session: local process (local=<workspace binary>) "
            "or remote connection to a USER-PROVIDED authorized CTF host and "
            "port (host=<host> port=<port>). Requires pwntools."
        ),
        parameters={
            "type": "object",
            "properties": {
                "local": {
                    "type": "string",
                    "description": "Relative path to a local challenge binary inside the workspace.",
                },
                "host": {
                    "type": "string",
                    "description": "User-provided authorized CTF host.",
                },
                "port": {
                    "type": "integer",
                    "description": "User-provided authorized CTF port.",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds.",
                },
            },
            "required": [],
        },
        required=[],
        timeout_seconds=30,
        category="binary",
    )

    registry.register(
        name="pwn_session_send",
        func=_pwn_session_send,
        description=(
            "Send a line to the active pwntools session (local or remote)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "data": {
                    "type": "string",
                    "description": "Line to send.",
                },
                "newline": {
                    "type": "boolean",
                    "description": "Append a newline (default true).",
                },
            },
            "required": ["data"],
        },
        required=["data"],
        timeout_seconds=15,
        category="binary",
    )

    registry.register(
        name="pwn_session_recv",
        func=_pwn_session_recv,
        description=(
            "Receive available output from the active pwntools session."
        ),
        parameters={
            "type": "object",
            "properties": {
                "timeout": {
                    "type": "number",
                    "description": "Receive timeout in seconds.",
                },
            },
            "required": [],
        },
        required=[],
        timeout_seconds=15,
        category="binary",
    )

    registry.register(
        name="pwn_session_wait_prompt",
        func=_pwn_session_wait_prompt,
        description=(
            "Wait for a prompt string in the active session and return output "
            "up to that point."
        ),
        parameters={
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "Prompt text to wait for.",
                },
                "timeout": {
                    "type": "number",
                    "description": "Wait timeout in seconds.",
                },
            },
            "required": ["prompt"],
        },
        required=["prompt"],
        timeout_seconds=20,
        category="binary",
    )

    registry.register(
        name="pwn_session_close",
        func=_pwn_session_close,
        description=(
            "Close the active pwntools session cleanly."
        ),
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
        required=[],
        timeout_seconds=10,
        category="binary",
    )

    registry.register(
        name="pwn_status",
        func=pwntools_status,
        description=(
            "Report whether optional pwntools is installed and whether a "
            "session is active."
        ),
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
        required=[],
        timeout_seconds=5,
        category="binary",
    )

    return registry


def _pwn_session_start(**kwargs) -> str:
    """Wrapper for pwn_session_start tool (needs workspace_root)."""
    return pwn_session_manager.start_local(
        kwargs.get("local", ""),
        kwargs.get("workspace_root"),
        kwargs.get("timeout", 10),
    ) if kwargs.get("local") else pwn_session_manager.connect_remote(
        kwargs.get("host", ""),
        int(kwargs.get("port", 0)),
        kwargs.get("timeout", 10),
    )


def _pwn_session_send(data: str, newline: bool = True) -> str:
    return pwn_session_manager.send(data, newline=newline)


def _pwn_session_recv(timeout: float = 2.0) -> str:
    return pwn_session_manager.recv(timeout=timeout)


def _pwn_session_wait_prompt(prompt: str, timeout: float = 10.0) -> str:
    return pwn_session_manager.wait_prompt(prompt, timeout=timeout)


def _pwn_session_close() -> str:
    return pwn_session_manager.close()


def main():
    """Run the interactive chat loop."""
    print("=" * 60)
    print("  CTF Agent - Stage 1+2+3+4+5+6: AI + Tools + Skills + Autonomous")
    print("=" * 60)
    print()

    # Parse CLI arguments (e.g. --sync-skills)
    parser = argparse.ArgumentParser(description="CTF Agent")
    parser.add_argument(
        "--sync-skills",
        action="store_true",
        help="Sync the skill library from SKILLS_REPOSITORY_URL and exit.",
    )
    cli_args, _ = parser.parse_known_args()

    # Load configuration
    config = Config.from_env()

    # Validate configuration
    errors = config.validate()
    if errors:
        print("Configuration errors:")
        for err in errors:
            print(f"  - {err}")
        print("\nPlease set the required environment variables and try again.")
        print("See .env.example for reference.")
        sys.exit(1)

    print(f"Provider : {config.provider}")
    print(f"Model    : {config.active_model}")
    print(f"Timeout  : {config.model_timeout}s")
    print(f"Workspace: {config.ctf_workspace}")
    print(f"Max steps: {config.max_agent_steps}")
    print(f"Skills   : {'enabled' if config.enable_skills else 'disabled'}")
    print()

    # Handle --sync-skills: sync the skill repository and exit.
    if cli_args.sync_skills:
        from tools.skill_sync import sync_skills_from_repo
        ok, msg = sync_skills_from_repo(
            config.skills_repository_url,
            branch=config.skills_repository_branch,
            sync_dir=config.skills_sync_directory,
        )
        print(msg)
        sys.exit(0 if ok else 1)

    # Create agent
    agent = ChatAgent(config)

    # Build and attach the tool registry
    tool_registry = _build_tool_registry(config)
    agent.set_tool_registry(tool_registry)

    # Initialize the skill system (registry + router)
    agent.init_skills()
    if config.enable_skills:
        print(agent.skill_summary())
        print()

    # Configure the shared HTTP session from config
    init_http_session_from_config(config)

    # Stage 7: configure the optional pwntools session policy from config
    init_pwn_session_from_config(config)

    # Validate provider connection
    try:
        agent.provider.validate_connection()
    except Exception as e:
        print(f"Provider connection error: {e}")
        print("You can still chat, but requests may fail.")
    print()

    print("Type your message, or use /help for commands. (Ctrl+C to exit)")
    print("-" * 60)

    while True:
        try:
            user_input = input("\nYou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not user_input:
            continue

        # Handle commands
        if user_input == "/exit":
            print("Goodbye!")
            break

        elif user_input == "/reset":
            agent.reset_conversation()
            print("Conversation history cleared.")
            continue

        elif user_input == "/help":
            print(HELP_TEXT)
            continue

        elif user_input == "/tools":
            _print_tools(tool_registry)
            continue

        elif user_input == "/session":
            print()
            print(session_manager.show_cookies())
            print()
            print(session_manager.show_headers())
            continue

        elif user_input.startswith("/model "):
            model_name = user_input[len("/model "):].strip()
            if not model_name:
                print("Usage: /model <model_name>")
                continue
            try:
                agent.set_model(model_name)
                print(f"Model set to: {model_name}")
            except Exception as e:
                print(f"Error setting model: {e}")
            continue

        elif user_input.startswith("/provider "):
            provider_name = user_input[len("/provider "):].strip().lower()
            if not provider_name:
                print("Usage: /provider <openrouter|opencode>")
                continue
            if provider_name not in ("openrouter", "opencode"):
                print(f"Unknown provider: {provider_name}. Use 'openrouter' or 'opencode'.")
                continue
            try:
                agent.set_provider(provider_name)
                print(f"Provider set to: {provider_name}")
            except Exception as e:
                print(f"Error setting provider: {e}")
            continue

        elif user_input in ("/skills", "/skill") or user_input.startswith("/skills ") or user_input.startswith("/skill "):
            print()
            print(agent.skill_command(user_input))
            continue

        elif user_input in ("/plan", "/memory", "/evidence", "/status"):
            print()
            print(agent.stage6_command(user_input))
            continue

        elif user_input == "/specialists" or user_input.startswith("/specialists "):
            print()
            print(agent.stage7_command(user_input))
            continue

        elif user_input == "/limits":
            print()
            print(agent.stage7_command(user_input))
            continue

        # Normal chat message (with tool calling)
        try:
            print("Agent> ", end="", flush=True)
            response = agent.send_message(user_input)
            print(response)
        except InvalidAPIKeyError as e:
            print(f"Authentication error: {e}")
        except UnsupportedModelError as e:
            print(f"Model error: {e}")
        except ProviderUnavailableError as e:
            print(f"Provider unavailable: {e}")
        except RateLimitError as e:
            print(f"Rate limit exceeded: {e}")
        except PaymentRequiredError as e:
            print(f"Payment required: {e}")
        except TimeoutError as e:
            print(f"Request timed out: {e}")
        except EmptyResponseError as e:
            print(f"Empty response from model: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")


def _print_tools(registry: ToolRegistry) -> None:
    """Print a formatted list of available tools."""
    import shutil

    tools = registry.list_tools()
    print()
    print("Available Tools:")
    print("-" * 60)
    for tool in tools:
        name = tool["name"]
        desc = tool["description"]
        # Check availability for command-based tools
        if name == "run_ctf_command":
            # Report which allowed commands exist on this OS
            allowed = [
                "file", "strings", "xxd", "hexdump", "readelf",
                "objdump", "nm", "ldd", "grep", "rg", "python", "python3",
                "checksec",
            ]
            present = sorted(c for c in allowed if shutil.which(c))
            missing = sorted(c for c in allowed if not shutil.which(c))
            avail_line = f"Commands available: {', '.join(present) if present else 'none'}"
            if missing:
                avail_line += f"\n{'':25s}   Commands missing (unavailable on this OS): {', '.join(missing)}"
        else:
            avail_line = "Available: Yes"
        print(f"  {name:25s} - {desc}")
        print(f"{'':25s}   {avail_line}")
    print("-" * 60)


if __name__ == "__main__":
    main()
