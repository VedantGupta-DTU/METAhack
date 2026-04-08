#!/usr/bin/env python3
"""
Baseline inference script for AppSecEnv — Application Security Auto-Patcher.

Runs all 15 vulnerability tasks with 3 baseline strategies and prints results.

Strategies:
    - Random: submits nonsense code (expected ~0.0)
    - Template: uses naive/partial fixes (expected ~0.3–0.5)
    - Oracle: correct, fully secure solutions (expected 1.0)

Usage:
    python baseline.py --direct
"""

from __future__ import annotations

import argparse
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server.tasks import ALL_TASKS, Task
from server.executor import execute_code
from server.kernel_env_environment import KernelEnvironment
from models import AppSecAction


# ===========================================================================
# Oracle solutions — correct, fully secure implementations
# ===========================================================================

ORACLE_SOLUTIONS = {
    # ---- E1: XSS Escape ----
    "e1_xss_escape": (
        "def render_user_greeting(name: str) -> str:\n"
        "    import html\n"
        "    safe_name = html.escape(name)\n"
        "    return f\"<div class='greeting'>Hello, {safe_name}!</div>\""
    ),

    # ---- E2: Path Traversal ----
    "e2_path_traversal": (
        "def resolve_file_path(base_directory: str, user_filename: str) -> str:\n"
        "    import os\n"
        "    base = os.path.normpath(os.path.abspath(base_directory))\n"
        "    full = os.path.normpath(os.path.join(base, user_filename))\n"
        "    if not full.startswith(base + os.sep) and full != base:\n"
        "        raise ValueError(f'Path traversal detected: {user_filename}')\n"
        "    return full"
    ),

    # ---- E3: SSRF Validation ----
    "e3_ssrf_validate": (
        "def validate_fetch_url(url: str) -> str:\n"
        "    from urllib.parse import urlparse\n"
        "    parsed = urlparse(url)\n"
        "    if parsed.scheme not in ('http', 'https'):\n"
        "        raise ValueError(f'Invalid scheme: {parsed.scheme}')\n"
        "    hostname = parsed.hostname or ''\n"
        "    hostname_lower = hostname.lower()\n"
        "    if hostname_lower in ('localhost', '127.0.0.1', '0.0.0.0', '::1'):\n"
        "        raise ValueError(f'Internal host blocked: {hostname}')\n"
        "    if hostname_lower.startswith('10.') or hostname_lower.startswith('192.168.'):\n"
        "        raise ValueError(f'Internal IP blocked: {hostname}')\n"
        "    if hostname_lower.startswith('172.'):\n"
        "        parts = hostname_lower.split('.')\n"
        "        if len(parts) >= 2 and 16 <= int(parts[1]) <= 31:\n"
        "            raise ValueError(f'Internal IP blocked: {hostname}')\n"
        "    if hostname_lower.startswith('169.254'):\n"
        "        raise ValueError(f'Link-local IP blocked: {hostname}')\n"
        "    return url"
    ),

    # ---- E4: Header Injection ----
    "e4_header_injection": (
        "def build_redirect_url(url: str) -> str:\n"
        "    if '\\r' in url or '\\n' in url:\n"
        "        raise ValueError('CRLF characters detected in URL')\n"
        "    return url"
    ),

    # ---- E5: Insecure Randomness ----
    "e5_insecure_random": (
        "def generate_reset_token(length: int = 16) -> str:\n"
        "    import secrets\n"
        "    return secrets.token_hex(length)"
    ),

    # ---- M1: Command Injection ----
    "m1_command_injection": (
        "def build_grep_command(pattern: str, filepath: str) -> list:\n"
        "    import re\n"
        "    if not re.match(r'^[a-zA-Z0-9 .\\-_]+$', pattern):\n"
        "        raise ValueError(f'Unsafe pattern: {pattern}')\n"
        "    return ['grep', pattern, filepath]"
    ),

    # ---- M2: Insecure Deserialization ----
    "m2_insecure_deserialize": (
        "def load_user_config(config_str: str) -> dict:\n"
        "    import json\n"
        "    try:\n"
        "        result = json.loads(config_str)\n"
        "    except json.JSONDecodeError as e:\n"
        "        raise ValueError(f'Invalid JSON: {e}')\n"
        "    if not isinstance(result, dict):\n"
        "        raise ValueError('Config must be a JSON object')\n"
        "    return result"
    ),

    # ---- M3: IDOR Access Control ----
    "m3_idor_access": (
        "def get_user_document(documents: dict, doc_id: str, requesting_user_id: str) -> dict:\n"
        "    if doc_id not in documents:\n"
        "        raise KeyError(f'Document {doc_id} not found')\n"
        "    doc = documents[doc_id]\n"
        "    if doc.get('owner_id') != requesting_user_id:\n"
        "        raise PermissionError(f'User {requesting_user_id} does not own document {doc_id}')\n"
        "    return doc"
    ),

    # ---- M4: Open Redirect ----
    "m4_open_redirect": (
        "def validate_redirect_target(url: str, allowed_domain: str) -> str:\n"
        "    from urllib.parse import urlparse\n"
        "    if url.startswith('/') and not url.startswith('//'):\n"
        "        return url\n"
        "    parsed = urlparse(url)\n"
        "    if not parsed.hostname:\n"
        "        raise ValueError('Invalid URL')\n"
        "    if parsed.hostname != allowed_domain and not parsed.hostname.endswith('.' + allowed_domain):\n"
        "        raise ValueError(f'External redirect blocked: {parsed.hostname}')\n"
        "    return url"
    ),

    # ---- M5: Log Injection ----
    "m5_log_injection": (
        "def format_log_entry(level: str, user_input: str, timestamp: str) -> str:\n"
        "    sanitized = user_input.replace('\\r', '').replace('\\n', ' ')\n"
        "    return f'[{timestamp}] {level}: User action - {sanitized}'"
    ),

    # ---- H1: JWT Bypass ----
    "h1_jwt_bypass": (
        "def verify_jwt_token(token: str, secret: str) -> dict:\n"
        "    import base64, json, hmac, hashlib\n"
        "    parts = token.split('.')\n"
        "    if len(parts) != 3:\n"
        "        raise ValueError('Invalid token format')\n"
        "    def b64decode(s):\n"
        "        padding = 4 - len(s) % 4\n"
        "        if padding != 4:\n"
        "            s += '=' * padding\n"
        "        return base64.urlsafe_b64decode(s)\n"
        "    header = json.loads(b64decode(parts[0]))\n"
        "    if header.get('alg', '').lower() == 'none':\n"
        "        raise ValueError('Algorithm none is not allowed')\n"
        "    if header.get('alg') != 'HS256':\n"
        "        raise ValueError(f'Unsupported algorithm: {header.get(\"alg\")}')\n"
        "    msg = f'{parts[0]}.{parts[1]}'.encode()\n"
        "    expected_sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()\n"
        "    actual_sig = b64decode(parts[2])\n"
        "    if not hmac.compare_digest(expected_sig, actual_sig):\n"
        "        raise ValueError('Invalid signature')\n"
        "    payload = json.loads(b64decode(parts[1]))\n"
        "    return payload"
    ),

    # ---- H2: ReDoS Prevention ----
    "h2_redos_prevention": (
        "def validate_email_pattern(email: str) -> bool:\n"
        "    import re\n"
        "    pattern = r'^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$'\n"
        "    return bool(re.match(pattern, email))"
    ),

    # ---- H3: Template Injection ----
    "h3_template_injection": (
        "def render_template_string(template: str, variables: dict) -> str:\n"
        "    import re\n"
        "    placeholders = re.findall(r'\\{([^}]+)\\}', template)\n"
        "    for p in placeholders:\n"
        "        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', p):\n"
        "            raise ValueError(f'Unsafe placeholder: {p}')\n"
        "    return template.format(**variables)"
    ),

    # ---- H4: Config Pollution ----
    "h4_config_pollution": (
        "def update_user_settings(current_config: dict, user_updates: dict) -> dict:\n"
        "    ALLOWED_KEYS = {'theme', 'language', 'timezone', 'notifications', 'page_size'}\n"
        "    config = current_config.copy()\n"
        "    for key, value in user_updates.items():\n"
        "        if key in ALLOWED_KEYS:\n"
        "            config[key] = value\n"
        "    return config"
    ),

    # ---- H5: Multi-Vulnerability Endpoint ----
    "h5_multi_vuln": (
        "def process_search_request(query: str, data: list, user_role: str, data_scope: str) -> dict:\n"
        "    import html\n"
        "    if data_scope == 'admin' and user_role != 'admin':\n"
        "        raise PermissionError('Admin access required')\n"
        "    safe_query = html.escape(query)\n"
        "    message = f'<p>Results for: {safe_query}</p>'\n"
        "    results = [item for item in data if query.lower() in item.lower()]\n"
        "    return {'message': message, 'results': results, 'count': len(results)}"
    ),
}


# ===========================================================================
# Template solutions — partial/naive fixes (some bugs remain)
# ===========================================================================

TEMPLATE_SOLUTIONS = {
    "e1_xss_escape": (
        "def render_user_greeting(name: str) -> str:\n"
        "    # Partial: only escapes <>, misses & and quotes\n"
        "    safe = name.replace('<', '').replace('>', '')\n"
        "    return f\"<div class='greeting'>Hello, {safe}!</div>\""
    ),
    "e2_path_traversal": (
        "def resolve_file_path(base_directory: str, user_filename: str) -> str:\n"
        "    import os\n"
        "    if '..' in user_filename:\n"
        "        raise ValueError('Traversal detected')\n"
        "    return os.path.join(base_directory, user_filename)"
    ),
    "e3_ssrf_validate": (
        "def validate_fetch_url(url: str) -> str:\n"
        "    if not url.startswith('http'):\n"
        "        raise ValueError('Invalid scheme')\n"
        "    return url"  # Bug: accepts http://localhost, file:// not fully blocked
    ),
    "e4_header_injection": (
        "def build_redirect_url(url: str) -> str:\n"
        "    return url.replace('\\n', '').replace('\\r', '')"  # Strips instead of raising
    ),
    "e5_insecure_random": (
        "def generate_reset_token(length: int = 16) -> str:\n"
        "    import random\n"
        "    chars = '0123456789abcdef'\n"
        "    return ''.join(random.choice(chars) for _ in range(length * 2))"
        # Bug: still uses random, not secrets
    ),
    "m1_command_injection": (
        "def build_grep_command(pattern: str, filepath: str) -> list:\n"
        "    return ['grep', pattern, filepath]"  # Bug: no pattern validation
    ),
    "m2_insecure_deserialize": (
        "def load_user_config(config_str: str) -> dict:\n"
        "    import json\n"
        "    return json.loads(config_str)"
    ),
    "m3_idor_access": (
        "def get_user_document(documents: dict, doc_id: str, requesting_user_id: str) -> dict:\n"
        "    if doc_id not in documents:\n"
        "        raise KeyError(f'Document {doc_id} not found')\n"
        "    return documents[doc_id]"  # Bug: still no ownership check
    ),
    "m4_open_redirect": (
        "def validate_redirect_target(url: str, allowed_domain: str) -> str:\n"
        "    if url.startswith('/'):\n"
        "        return url\n"  # Bug: accepts //evil.com
        "    return url"
    ),
    "m5_log_injection": (
        "def format_log_entry(level: str, user_input: str, timestamp: str) -> str:\n"
        "    sanitized = user_input.replace('\\n', ' ')\n"  # Bug: doesn't replace \r
        "    return f'[{timestamp}] {level}: User action - {sanitized}'"
    ),
    "h1_jwt_bypass": (
        "def verify_jwt_token(token: str, secret: str) -> dict:\n"
        "    import base64, json\n"
        "    parts = token.split('.')\n"
        "    if len(parts) != 3:\n"
        "        raise ValueError('Invalid token format')\n"
        "    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))\n"
        "    return payload"  # Bug: still no signature check
    ),
    "h2_redos_prevention": (
        "def validate_email_pattern(email: str) -> bool:\n"
        "    return '@' in email and '.' in email"  # Bug: too permissive
    ),
    "h3_template_injection": (
        "def render_template_string(template: str, variables: dict) -> str:\n"
        "    return template.format(**variables)"  # Bug: still vulnerable
    ),
    "h4_config_pollution": (
        "def update_user_settings(current_config: dict, user_updates: dict) -> dict:\n"
        "    config = current_config.copy()\n"
        "    config.update(user_updates)\n"  # Bug: still accepts all keys
        "    return config"
    ),
    "h5_multi_vuln": (
        "def process_search_request(query: str, data: list, user_role: str, data_scope: str) -> dict:\n"
        "    message = f'<p>Results for: {query}</p>'\n"  # Bug: still XSS-vulnerable
        "    results = [item for item in data if query.lower() in item.lower()]\n"
        "    return {'message': message, 'results': results, 'count': len(results)}"
    ),
}


# ===========================================================================
# Running baselines
# ===========================================================================

def run_baseline_direct():
    """Run baselines directly using the environment class (no server needed)."""
    env = KernelEnvironment()

    strategies = {
        "Random": lambda task: "def f(): return 42",
        "Template": lambda task: TEMPLATE_SOLUTIONS.get(task.task_id, "pass"),
        "Oracle": lambda task: ORACLE_SOLUTIONS.get(task.task_id, "pass"),
    }

    # Header
    print()
    print(f"{'Task':<30} {'Vuln Type':<20} {'Diff':<8}", end="")
    for name in strategies:
        print(f" {name:>10}", end="")
    print()
    print("-" * 85)

    totals = {name: 0.0 for name in strategies}

    for task in ALL_TASKS:
        print(f"{task.task_id:<30} {task.vulnerability_type[:18]:<20} {task.difficulty:<8}", end="")

        for strat_name, strat_fn in strategies.items():
            # Reset with specific task
            env.reset(task_id=task.task_id)

            # Submit code
            code = strat_fn(task)
            obs = env.step(AppSecAction(code=code))

            reward = obs.reward if obs.reward is not None else 0.0
            totals[strat_name] += reward

            print(f" {reward:>10.2f}", end="")

        print()

    # Averages
    print("-" * 85)
    n = len(ALL_TASKS)
    print(f"{'AVERAGE':<30} {'':<20} {'':<8}", end="")
    for name in strategies:
        avg = totals[name] / n
        print(f" {avg:>10.2f}", end="")
    print()
    print()


def main():
    parser = argparse.ArgumentParser(description="AppSecEnv Baseline Inference")
    parser.add_argument(
        "--url",
        type=str,
        default=None,
        help="URL of a running AppSecEnv server (e.g., http://localhost:8000)",
    )
    parser.add_argument(
        "--direct",
        action="store_true",
        default=True,
        help="Run directly without a server (default)",
    )
    args = parser.parse_args()

    if args.url:
        print("Server mode not yet implemented. Use --direct for now.")
        print("Running direct baselines instead...")

    print("=" * 85)
    print("AppSecEnv — Baseline Inference")
    print("Dual Grading: 0.5 × Functional + 0.5 × Security")
    print("=" * 85)

    run_baseline_direct()


if __name__ == "__main__":
    main()
