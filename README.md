---
title: AppSecEnv — Vulnerability Auto-Patcher
emoji: 🛡️
colorFrom: red
colorTo: yellow
sdk: docker
pinned: false
app_port: 8000
base_path: /web
tags:
  - openenv
---

# AppSecEnv — Application Security Vulnerability Auto-Patcher

AppSecEnv is a real-world OpenEnv environment where an agent receives vulnerable Python code and must patch it while preserving business logic.  
The grader is dual-objective:

- Functional correctness (normal input still works)
- Exploit resistance (malicious input is safely blocked)

Final reward:

`reward = 0.5 * functional_score + 0.5 * security_score`

This design prevents trivial reward hacks like deleting functionality just to block exploits.

## Why this is real-world

This mirrors an actual enterprise AppSec workflow:

- Triage vulnerable code
- Apply a secure fix
- Verify no regression in product behavior
- Validate exploit payloads are neutralized

## OpenEnv Interface

### Action

- `AppSecAction.code: str`  
  Full patched function implementation submitted by the agent.

### Observation

- `task_id`, `task_description`, `difficulty`
- `vulnerability_type`, `cwe_id`
- `vulnerable_code`, `function_signature`
- `functional_tests_passed`, `functional_tests_total`
- `security_tests_passed`, `security_tests_total`
- `functional_score`, `security_score`
- `test_summary`, `test_feedback`
- `stdout`, `stderr`
- `attempts_used`, `attempts_remaining`

### State

- `episode_id`, `step_count`
- `task_id`, `difficulty`
- `max_attempts`, `best_score`

## Task Bank (15 tasks, easy → medium → hard)

### Easy
- `e1_xss_escape`
- `e2_path_traversal`
- `e3_ssrf_validate`
- `e4_header_injection`
- `e5_insecure_random`

### Medium
- `m1_command_injection`
- `m2_insecure_deserialize`
- `m3_idor_access`
- `m4_open_redirect`
- `m5_log_injection`

### Hard
- `h1_jwt_bypass`
- `h2_redos_prevention`
- `h3_template_injection`
- `h4_config_pollution`
- `h5_multi_vuln`

Each task includes deterministic functional and exploit tests with a normalized score in `[0.0, 1.0]`.

## Reward Design

- Partial credit is provided throughout the trajectory
- Both objective components must be high to get high reward
- Small non-zero fallback reward (`0.02`) for safely executing code with no tests passed
- Efficiency bonus when all tests pass in fewer attempts

## Local Validation

```bash
cd kernel_env
.venv/bin/openenv validate
```

## Local Run

```bash
cd kernel_env
.venv/bin/uvicorn server.app:app --host 0.0.0.0 --port 8000
```

## Docker

```bash
cd kernel_env
docker build -t kernel_env:latest -f server/Dockerfile .
docker run -p 8000:8000 kernel_env:latest
```

## Required Inference File

- Root-level `inference.py` is included
- Uses OpenAI client and reads:
  - `API_BASE_URL`
  - `MODEL_NAME`
  - `HF_TOKEN`
  - `LOCAL_IMAGE_NAME`
- Emits required `[START]`, `[STEP]`, `[END]` log lines

## Deploy to Hugging Face Spaces

```bash
cd kernel_env
.venv/bin/openenv push --repo-id <username>/kernel-env
```
