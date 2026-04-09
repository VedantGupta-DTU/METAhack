"""
AppSecEnv — Application Security Vulnerability Auto-Patcher.

A real-world OpenEnv environment where an AI agent receives vulnerable code
and must patch security vulnerabilities without breaking business logic.
Dual-graded: functional correctness (50%) + security effectiveness (50%).
"""

from __future__ import annotations

from typing import Any, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment

try:
    from ..models import AppSecAction, AppSecObservation, AppSecState
except ImportError:
    from models import AppSecAction, AppSecObservation, AppSecState

try:
    from .executor import execute_code
    from .tasks import Task, get_task, ALL_TASKS, TASK_BY_ID
except ImportError:
    from server.executor import execute_code
    from server.tasks import Task, get_task, ALL_TASKS, TASK_BY_ID


MAX_ATTEMPTS = 10


def _clamp(v: float) -> float:
    """Clamp a score strictly into (0, 1) — never 0.0, never 1.0."""
    return max(0.01, min(0.99, float(v)))


class KernelEnvironment(Environment):
    """
    Application Security Vulnerability Auto-Patcher Environment.

    The agent receives vulnerable Python code with a described security flaw.
    It submits a patched version which is tested against:
      - Functional tests: normal inputs must work correctly
      - Exploit tests: malicious inputs must be blocked

    Reward = 0.5 * functional_score + 0.5 * security_score
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self):
        super().__init__()
        self._state = AppSecState(episode_id=str(uuid4()), step_count=0)
        self._current_task: Optional[Task] = None

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> AppSecObservation:
        """Reset and present a new vulnerability to patch."""
        task_id = kwargs.get("task_id", None)
        difficulty = kwargs.get("difficulty", None)

        self._current_task = get_task(task_id=task_id, difficulty=difficulty, seed=seed)

        self._state = AppSecState(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
            task_id=self._current_task.task_id,
            difficulty=self._current_task.difficulty,
            max_attempts=MAX_ATTEMPTS,
            best_score=0.01,
        )

        func_tests = [tc for tc in self._current_task.test_cases if tc.test_type == "functional"]
        sec_tests = [tc for tc in self._current_task.test_cases if tc.test_type == "exploit"]

        return AppSecObservation(
            done=False,
            reward=0.01,
            task_id=self._current_task.task_id,
            task_description=self._current_task.description,
            vulnerability_type=self._current_task.vulnerability_type,
            cwe_id=self._current_task.cwe_id,
            vulnerable_code=self._current_task.vulnerable_code,
            function_signature=self._current_task.function_signature,
            difficulty=self._current_task.difficulty,
            stdout="",
            stderr="",
            test_summary=f"0/{len(func_tests)} functional, 0/{len(sec_tests)} security",
            functional_tests_passed=0,
            functional_tests_total=len(func_tests),
            security_tests_passed=0,
            security_tests_total=len(sec_tests),
            functional_score=0.01,
            security_score=0.01,
            test_feedback=[],
            attempts_remaining=MAX_ATTEMPTS,
            attempts_used=0,
        )

    def step(
        self,
        action: AppSecAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> AppSecObservation:
        """Execute agent's patched code and grade it."""
        if self._current_task is None:
            return AppSecObservation(
                done=True, reward=0.01,
                functional_score=0.01,
                security_score=0.01,
                stderr="Error: No task loaded. Call reset() first.",
            )

        self._state.step_count += 1
        task = self._current_task

        # Serialize test cases
        test_cases_data = [
            {
                "input_args": list(tc.input_args),
                "input_kwargs": tc.input_kwargs,
                "expected_output": tc.expected_output,
                "description": tc.description,
                "test_type": tc.test_type,
                "exploit_payload": tc.exploit_payload,
            }
            for tc in task.test_cases
        ]

        exec_timeout = timeout_s or task.time_limit_s
        exec_result = execute_code(
            agent_code=action.code,
            function_name=task.function_name,
            test_cases=test_cases_data,
            timeout_s=exec_timeout,
        )

        # Compute dual scores
        func_total = exec_result.functional_total
        func_passed = exec_result.functional_passed
        sec_total = exec_result.security_total
        sec_passed = exec_result.security_passed

        functional_score = func_passed / func_total if func_total > 0 else 0.0
        security_score = sec_passed / sec_total if sec_total > 0 else 0.0

        # Clamp individual scores strictly into (0, 1)
        functional_score = _clamp(functional_score)
        security_score = _clamp(security_score)

        # Reward = 50% functional + 50% security
        reward = 0.5 * functional_score + 0.5 * security_score

        # Small bonus for code that runs without errors
        if exec_result.success and reward <= 0.02:
            reward = 0.02

        # Efficiency bonus for solving in fewer attempts
        attempts_remaining = MAX_ATTEMPTS - self._state.step_count
        if functional_score >= 0.98 and security_score >= 0.98:
            efficiency_bonus = 0.04 * (attempts_remaining / MAX_ATTEMPTS)
            reward = reward + efficiency_bonus

        # Final clamp on ALL scores — Phase 2 Deep Validation
        reward = _clamp(reward)
        functional_score = _clamp(functional_score)
        security_score = _clamp(security_score)

        self._state.best_score = _clamp(max(self._state.best_score, reward))

        # Build feedback
        test_feedback = []
        for tr in exec_result.test_results:
            tag = "🛡️ SEC" if tr.test_type == "exploit" else "⚙️ FUNC"
            status = "✓ PASS" if tr.passed else "✗ FAIL"
            msg = f"{tag} {status}: {tr.description}"
            if not tr.passed and tr.error:
                msg += f" — {tr.error}"
            test_feedback.append(msg)

        # Episode done?
        all_passed = (func_passed == func_total and sec_passed == sec_total
                      and func_total > 0 and sec_total > 0)
        out_of_attempts = self._state.step_count >= MAX_ATTEMPTS
        done = all_passed or out_of_attempts

        # Summary
        test_summary = (
            f"{func_passed}/{func_total} functional, "
            f"{sec_passed}/{sec_total} security"
        )
        if exec_result.timed_out:
            test_summary = f"TIMEOUT — {test_summary}"
        elif exec_result.error_type and not exec_result.success:
            test_summary = f"{exec_result.error_type} — {test_summary}"

        return AppSecObservation(
            done=done,
            reward=reward,
            task_id=task.task_id,
            task_description=task.description,
            vulnerability_type=task.vulnerability_type,
            cwe_id=task.cwe_id,
            vulnerable_code=task.vulnerable_code,
            function_signature=task.function_signature,
            difficulty=task.difficulty,
            stdout=exec_result.stdout[:2000],
            stderr=exec_result.stderr[:2000],
            test_summary=test_summary,
            functional_tests_passed=func_passed,
            functional_tests_total=func_total,
            security_tests_passed=sec_passed,
            security_tests_total=sec_total,
            functional_score=functional_score,
            security_score=security_score,
            test_feedback=test_feedback,
            attempts_remaining=max(0, MAX_ATTEMPTS - self._state.step_count),
            attempts_used=self._state.step_count,
        )

    @property
    def state(self) -> AppSecState:
        return self._state
