#!/usr/bin/env python3
"""
Comprehensive unit tests for KernelEnv.

Tests:
  1. Executor — known-good code, known-bad code, syntax errors, timeouts
  2. Grader — all 15 tasks with oracle solutions, verify score = 1.0
  3. Environment — reset/step/state lifecycle
"""

from __future__ import annotations

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server.executor import execute_code, ExecutionResult, TestResult
from server.tasks import ALL_TASKS, TASK_BY_ID, get_task
from server.kernel_env_environment import KernelEnvironment
from models import KernelAction, KernelObservation, KernelState

# Oracle solutions from baseline.py
from baseline import ORACLE_SOLUTIONS

# ───────────────────────────────────────────────────────────────────
# ANSI colors for pretty output
# ───────────────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

passed_count = 0
failed_count = 0


def _ok(name: str, detail: str = ""):
    global passed_count
    passed_count += 1
    d = f" — {detail}" if detail else ""
    print(f"  {GREEN}✓ PASS{RESET}: {name}{d}")


def _fail(name: str, detail: str = ""):
    global failed_count
    failed_count += 1
    d = f" — {detail}" if detail else ""
    print(f"  {RED}✗ FAIL{RESET}: {name}{d}")


# ───────────────────────────────────────────────────────────────────
# 1. EXECUTOR TESTS
# ───────────────────────────────────────────────────────────────────
def test_executor():
    print(f"\n{BOLD}═══ 1. EXECUTOR UNIT TESTS ═══{RESET}\n")

    # 1a. Known-good code runs successfully
    result = execute_code(
        agent_code="def add(a, b): return a + b",
        function_name="add",
        test_cases=[
            {"input_args": [1, 2], "input_kwargs": {}, "expected_output": 3, "description": "1+2=3"},
            {"input_args": [0, 0], "input_kwargs": {}, "expected_output": 0, "description": "0+0=0"},
        ],
        timeout_s=5.0,
    )
    if result.success and result.tests_passed == 2:
        _ok("Known-good code", f"{result.tests_passed}/{result.tests_total} passed")
    else:
        _fail("Known-good code", f"success={result.success}, passed={result.tests_passed}/{result.tests_total}, stderr={result.stderr}")

    # 1b. Syntax error is caught
    result = execute_code(
        agent_code="def broken( return",
        function_name="broken",
        test_cases=[
            {"input_args": [], "input_kwargs": {}, "expected_output": None, "description": "syntax error test"},
        ],
        timeout_s=5.0,
    )
    if not result.success or result.tests_passed == 0:
        _ok("Syntax error detection", f"success={result.success}, error_type={result.error_type}")
    else:
        _fail("Syntax error detection", f"Expected failure, got success={result.success}")

    # 1c. Runtime error is caught
    result = execute_code(
        agent_code="def crasher(): raise ValueError('boom')",
        function_name="crasher",
        test_cases=[
            {"input_args": [], "input_kwargs": {}, "expected_output": None, "description": "runtime error test"},
        ],
        timeout_s=5.0,
    )
    if result.tests_passed == 0:
        _ok("Runtime error handling", f"tests_passed=0 as expected")
    else:
        _fail("Runtime error handling", f"tests_passed={result.tests_passed}")

    # 1d. Missing function name
    result = execute_code(
        agent_code="def wrong_name(): return 42",
        function_name="expected_name",
        test_cases=[
            {"input_args": [], "input_kwargs": {}, "expected_output": 42, "description": "wrong name test"},
        ],
        timeout_s=5.0,
    )
    if result.tests_passed == 0:
        _ok("Missing function detection", f"Correctly detected missing function")
    else:
        _fail("Missing function detection", f"Should have 0 passed, got {result.tests_passed}")

    # 1e. Timeout detection (code that runs forever)
    result = execute_code(
        agent_code="def slow():\n    import time\n    time.sleep(100)\n    return 1",
        function_name="slow",
        test_cases=[
            {"input_args": [], "input_kwargs": {}, "expected_output": 1, "description": "timeout test"},
        ],
        timeout_s=2.0,
    )
    if result.timed_out:
        _ok("Timeout detection", f"timed_out=True after 2s")
    else:
        _fail("Timeout detection", f"timed_out={result.timed_out}")

    # 1f. Partial test pass (some pass, some fail)
    result = execute_code(
        agent_code="def identity(x): return x",
        function_name="identity",
        test_cases=[
            {"input_args": [1], "input_kwargs": {}, "expected_output": 1, "description": "pass"},
            {"input_args": [2], "input_kwargs": {}, "expected_output": 99, "description": "fail"},
            {"input_args": [3], "input_kwargs": {}, "expected_output": 3, "description": "pass2"},
        ],
        timeout_s=5.0,
    )
    if result.tests_passed == 2 and result.tests_total == 3:
        _ok("Partial pass", f"{result.tests_passed}/{result.tests_total} as expected")
    else:
        _fail("Partial pass", f"{result.tests_passed}/{result.tests_total}")

    # 1g. stdout capture
    result = execute_code(
        agent_code='print("hello world")\ndef noop(): return None',
        function_name="noop",
        test_cases=[
            {"input_args": [], "input_kwargs": {}, "expected_output": None, "description": "stdout capture"},
        ],
        timeout_s=5.0,
    )
    if "hello world" in result.stdout:
        _ok("Stdout capture", f"Captured: {result.stdout!r}")
    else:
        _fail("Stdout capture", f"Expected 'hello world' in stdout, got: {result.stdout!r}")


# ───────────────────────────────────────────────────────────────────
# 2. GRADER TESTS — Oracle solutions on all 15 tasks
# ───────────────────────────────────────────────────────────────────
def test_grader_oracle():
    print(f"\n{BOLD}═══ 2. GRADER — ORACLE SOLUTIONS (all 15 tasks) ═══{RESET}\n")

    env = KernelEnvironment()
    all_pass = True

    for task in ALL_TASKS:
        oracle_code = ORACLE_SOLUTIONS.get(task.task_id)
        if not oracle_code:
            _fail(f"{task.task_id}", "No oracle solution found in baseline.py")
            all_pass = False
            continue

        # Reset to this specific task
        env.reset(task_id=task.task_id)

        # Step with oracle code
        obs = env.step(KernelAction(code=oracle_code))

        reward = obs.reward if obs.reward is not None else 0.0
        # Oracle should get at least 1.0 (with efficiency bonus it could be > 1.0 but capped)
        if obs.tests_passed == obs.tests_total and obs.tests_total > 0 and reward >= 1.0:
            _ok(f"{task.task_id} [{task.difficulty}]", f"{obs.tests_passed}/{obs.tests_total} | reward={reward:.2f}")
        else:
            _fail(f"{task.task_id} [{task.difficulty}]",
                  f"{obs.tests_passed}/{obs.tests_total} | reward={reward:.2f} | feedback={obs.test_feedback}")
            all_pass = False

    return all_pass


# ───────────────────────────────────────────────────────────────────
# 3. ENVIRONMENT LIFECYCLE TESTS
# ───────────────────────────────────────────────────────────────────
def test_environment_lifecycle():
    print(f"\n{BOLD}═══ 3. ENVIRONMENT LIFECYCLE TESTS ═══{RESET}\n")

    env = KernelEnvironment()

    # 3a. Reset returns valid observation
    obs = env.reset(task_id="e1_reverse_string")
    if obs.task_id == "e1_reverse_string" and obs.difficulty == "easy" and obs.done is False:
        _ok("Reset returns correct observation",
            f"task_id={obs.task_id}, difficulty={obs.difficulty}, done={obs.done}")
    else:
        _fail("Reset returns correct observation",
              f"task_id={obs.task_id}, difficulty={obs.difficulty}, done={obs.done}")

    # 3b. State reflects current episode
    state = env.state
    if state.task_id == "e1_reverse_string" and state.step_count == 0:
        _ok("State after reset", f"task_id={state.task_id}, step_count={state.step_count}")
    else:
        _fail("State after reset", f"task_id={state.task_id}, step_count={state.step_count}")

    # 3c. Step increments step_count
    obs = env.step(KernelAction(code="def reverse_string(s): return 'wrong'"))
    state = env.state
    if state.step_count == 1:
        _ok("Step increments step_count", f"step_count={state.step_count}")
    else:
        _fail("Step increments step_count", f"step_count={state.step_count}")

    # 3d. Attempts remaining decreases
    if obs.attempts_remaining == 9 and obs.attempts_used == 1:
        _ok("Attempts tracking", f"remaining={obs.attempts_remaining}, used={obs.attempts_used}")
    else:
        _fail("Attempts tracking", f"remaining={obs.attempts_remaining}, used={obs.attempts_used}")

    # 3e. Solving task sets done=True
    env.reset(task_id="e1_reverse_string")
    obs = env.step(KernelAction(code="def reverse_string(s): return s[::-1]"))
    if obs.done is True and obs.tests_passed == obs.tests_total:
        _ok("Solving sets done=True", f"done={obs.done}, {obs.tests_passed}/{obs.tests_total}")
    else:
        _fail("Solving sets done=True", f"done={obs.done}, {obs.tests_passed}/{obs.tests_total}")

    # 3f. Best score never decreases
    env.reset(task_id="e3_count_vowels")
    # First: partial solution
    env.step(KernelAction(code="def count_vowels(s): return sum(1 for c in s if c in 'aeiou')"))
    score_after_partial = env.state.best_score
    # Second: worse solution
    env.step(KernelAction(code="def count_vowels(s): return 0"))
    score_after_worse = env.state.best_score
    if score_after_worse >= score_after_partial:
        _ok("Best score never decreases", f"partial={score_after_partial:.2f}, after_worse={score_after_worse:.2f}")
    else:
        _fail("Best score never decreases", f"partial={score_after_partial:.2f}, after_worse={score_after_worse:.2f}")

    # 3g. Step without reset returns error observation
    env2 = KernelEnvironment()
    obs = env2.step(KernelAction(code="def f(): pass"))
    if obs.done is True and "reset" in obs.stderr.lower():
        _ok("Step without reset", f"Returns error: {obs.stderr[:60]}")
    else:
        _fail("Step without reset", f"done={obs.done}, stderr={obs.stderr[:60]}")

    # 3h. Random task selection works
    env.reset(seed=42)
    state = env.state
    if state.task_id and state.difficulty:
        _ok("Random task selection", f"Random seed=42 → task={state.task_id}, diff={state.difficulty}")
    else:
        _fail("Random task selection", f"task_id={state.task_id}")

    # 3i. Difficulty-based selection
    env.reset(difficulty="hard")
    state = env.state
    if state.difficulty == "hard":
        _ok("Difficulty-based selection", f"task={state.task_id}")
    else:
        _fail("Difficulty-based selection", f"Got difficulty={state.difficulty}")


# ───────────────────────────────────────────────────────────────────
# 4. TASK BANK TESTS
# ───────────────────────────────────────────────────────────────────
def test_task_bank():
    print(f"\n{BOLD}═══ 4. TASK BANK TESTS ═══{RESET}\n")

    # 4a. 15 tasks total
    if len(ALL_TASKS) == 15:
        _ok("Total tasks", f"{len(ALL_TASKS)} tasks")
    else:
        _fail("Total tasks", f"Expected 15, got {len(ALL_TASKS)}")

    # 4b. 5 easy, 5 medium, 5 hard
    easy = [t for t in ALL_TASKS if t.difficulty == "easy"]
    medium = [t for t in ALL_TASKS if t.difficulty == "medium"]
    hard = [t for t in ALL_TASKS if t.difficulty == "hard"]
    if len(easy) == 5 and len(medium) == 5 and len(hard) == 5:
        _ok("Difficulty distribution", f"easy={len(easy)}, medium={len(medium)}, hard={len(hard)}")
    else:
        _fail("Difficulty distribution", f"easy={len(easy)}, medium={len(medium)}, hard={len(hard)}")

    # 4c. All tasks have 4+ test cases
    all_have_enough = True
    for t in ALL_TASKS:
        if len(t.test_cases) < 4:
            _fail(f"{t.task_id} test cases", f"Only {len(t.test_cases)} (need ≥ 4)")
            all_have_enough = False
    if all_have_enough:
        tc_counts = [len(t.test_cases) for t in ALL_TASKS]
        _ok("All tasks have ≥4 test cases", f"counts: {tc_counts}")

    # 4d. All tasks have required fields
    for t in ALL_TASKS:
        if t.task_id and t.description and t.function_signature and t.function_name:
            pass  # good
        else:
            _fail(f"{t.task_id} fields", "Missing required field")
    _ok("All tasks have required fields")

    # 4e. Unique task IDs
    ids = [t.task_id for t in ALL_TASKS]
    if len(ids) == len(set(ids)):
        _ok("Unique task IDs")
    else:
        _fail("Unique task IDs", f"Duplicates found")

    # 4f. get_task works by ID
    t = get_task(task_id="m2_two_sum")
    if t.task_id == "m2_two_sum":
        _ok("get_task by ID", f"Retrieved {t.task_id}")
    else:
        _fail("get_task by ID")

    # 4g. get_task raises on invalid ID
    try:
        get_task(task_id="nonexistent_task")
        _fail("get_task invalid ID", "Should raise ValueError")
    except ValueError:
        _ok("get_task raises on invalid ID")


# ───────────────────────────────────────────────────────────────────
# 5. MODEL TESTS
# ───────────────────────────────────────────────────────────────────
def test_models():
    print(f"\n{BOLD}═══ 5. MODEL TESTS ═══{RESET}\n")

    # 5a. KernelAction can be created
    action = KernelAction(code="print('hello')")
    if action.code == "print('hello')":
        _ok("KernelAction creation")
    else:
        _fail("KernelAction creation")

    # 5b. KernelObservation defaults
    obs = KernelObservation()
    if obs.task_id == "" and obs.tests_passed == 0 and obs.done is False:
        _ok("KernelObservation defaults")
    else:
        _fail("KernelObservation defaults")

    # 5c. KernelState defaults
    state = KernelState()
    if state.max_attempts == 10 and state.best_score == 0.0:
        _ok("KernelState defaults")
    else:
        _fail("KernelState defaults")


# ───────────────────────────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{BOLD}{'=' * 60}")
    print("  KernelEnv — Comprehensive Test Suite")
    print(f"{'=' * 60}{RESET}")

    test_executor()
    test_grader_oracle()
    test_environment_lifecycle()
    test_task_bank()
    test_models()

    print(f"\n{BOLD}{'=' * 60}")
    print(f"  RESULTS: {GREEN}{passed_count} passed{RESET}{BOLD}, {RED if failed_count else GREEN}{failed_count} failed{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}\n")

    sys.exit(1 if failed_count > 0 else 0)
