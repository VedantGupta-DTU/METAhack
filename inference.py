#!/usr/bin/env python3
"""
Inference Script for AppSecEnv — Application Security Vulnerability Auto-Patcher
=================================================================================
MANDATORY
- Before submitting, ensure the following variables are defined in your environment configuration:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.
    LOCAL_IMAGE_NAME The name of the local image to use for the environment

- The inference script must be named `inference.py` and placed in the root directory of the project
- Participants must use OpenAI Client for all LLM calls using above variables

STDOUT FORMAT
- The script must emit exactly three line types to stdout, in this order:
    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> rewards=<r1,r2,...,rn>
"""

import os
import sys
import textwrap
import time

from openai import OpenAI
from openai import APIConnectionError, APIStatusError, AuthenticationError, RateLimitError

# ---- Configuration ----
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN", "")
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME", "kernel_env:latest")
MAX_LLM_RETRIES = int(os.getenv("MAX_LLM_RETRIES", "2"))

# ---- LLM Client ----
client = OpenAI(
    base_url=API_BASE_URL,
    api_key=HF_TOKEN or "dummy",
)

# ---- Environment Setup ----
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from server.kernel_env_environment import KernelEnvironment
from models import AppSecAction

ENV_NAME = "appsec-env"


def build_system_prompt():
    return textwrap.dedent("""\
    You are an expert Application Security Engineer. You will be given vulnerable Python code
    and a description of the security vulnerability. Your job is to rewrite the function to
    fix the vulnerability WITHOUT breaking the existing business logic.

    Rules:
    1. Keep the same function signature
    2. The fixed function must still work correctly for normal, legitimate inputs
    3. Malicious/exploit inputs must be blocked (raise ValueError, PermissionError, etc.) or handled safely
    4. Only output the fixed Python function code, nothing else
    5. Do not include markdown formatting, just raw Python code
    6. Do not include any explanation, just the code
    """)


def build_user_prompt(obs):
    return textwrap.dedent(f"""\
    ## Vulnerability: {obs.vulnerability_type} ({obs.cwe_id})
    ## Difficulty: {obs.difficulty}

    ### Task Description:
    {obs.task_description}

    ### Vulnerable Code:
    ```python
    {obs.vulnerable_code}
    ```

    ### Expected Function Signature:
    {obs.function_signature}

    ### Current Test Results:
    {obs.test_summary}

    ### Feedback:
    {chr(10).join(obs.test_feedback) if obs.test_feedback else "No feedback yet — this is your first attempt."}

    Write the FIXED version of the function. Output ONLY the Python code, no explanation.
    """)


def call_llm(system_prompt, user_prompt):
    """Call the LLM via OpenAI-compatible API."""
    attempts = MAX_LLM_RETRIES + 1
    last_error = "unknown"
    for attempt_idx in range(attempts):
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
                max_tokens=2048,
            )
            content = response.choices[0].message.content.strip()
            if content.startswith("```python"):
                content = content[len("```python"):].strip()
            if content.startswith("```"):
                content = content[3:].strip()
            if content.endswith("```"):
                content = content[:-3].strip()
            return content, None
        except AuthenticationError:
            last_error = "auth_error_invalid_hf_token"
            break
        except RateLimitError:
            last_error = "rate_limit_exceeded"
        except APIConnectionError:
            last_error = "api_connection_error"
        except APIStatusError as e:
            last_error = f"api_status_{e.status_code}"
            if 400 <= e.status_code < 500 and e.status_code != 429:
                break
        except Exception as e:  # pragma: no cover
            last_error = f"unexpected_{type(e).__name__}"

        if attempt_idx < attempts - 1:
            time.sleep(1.5 * (attempt_idx + 1))

    return f"# LLM Error: {last_error}\ndef placeholder(): pass", last_error


def run_task(task_id, max_steps=5):
    """Run a single task and return the results."""
    env = KernelEnvironment()
    obs = env.reset(task_id=task_id)

    print(f"[START] task={task_id} env={ENV_NAME} model={MODEL_NAME}")

    system_prompt = build_system_prompt()
    rewards = []
    success = False
    steps = 0

    for step_num in range(1, max_steps + 1):
        steps = step_num
        user_prompt = build_user_prompt(obs)
        code, llm_error = call_llm(system_prompt, user_prompt)

        # Execute step
        action = AppSecAction(code=code)
        obs = env.step(action)

        reward = obs.reward if obs.reward is not None else 0.0
        rewards.append(reward)
        done = obs.done

        # Truncate action for logging
        action_short = code.replace('\n', ' ')[:80]
        error_msg = "null"
        if llm_error:
            error_msg = llm_error
        if obs.stderr:
            error_msg = obs.stderr.replace("\n", " ").strip()

        print(
            f"[STEP] step={step_num} action={action_short} reward={reward:.2f} "
            f"done={'true' if done else 'false'} error={error_msg}"
        )

        if done:
            if reward >= 0.9:
                success = True
            break

    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={'true' if success else 'false'} steps={steps} rewards={rewards_str}")

    return {"task_id": task_id, "success": success, "steps": steps, "rewards": rewards}


def main():
    """Run baseline inference on exactly three tasks (easy/medium/hard)."""
    selected_tasks = [
        "e1_xss_escape",
        "m1_command_injection",
        "h3_template_injection",
    ]
    for task_id in selected_tasks:
        run_task(task_id, max_steps=3)


if __name__ == "__main__":
    main()
