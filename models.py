"""
Data models for AppSecEnv — Application Security Vulnerability Auto-Patcher.

The agent receives vulnerable code snippets and must rewrite them to fix
security vulnerabilities without breaking business logic. Graded via
dual testing: functional correctness + exploit prevention.
"""

from typing import Dict, List, Optional

from openenv.core.env_server.types import Action, Observation, State
from pydantic import Field, model_validator


def _clamp_score(v: float | int | bool | None) -> float:
    """Clamp any score strictly into (0, 1) — never 0.0, never 1.0."""
    if v is None:
        return 0.01
    return max(0.01, min(0.99, float(v)))


class AppSecAction(Action):
    """Action: the agent submits patched Python code."""

    code: str = Field(..., description="Fixed Python code that patches the vulnerability")


class AppSecObservation(Observation):
    """Observation returned after each step.

    Contains the task info, vulnerable code, execution results,
    and the dual-grading breakdown (functional vs security).
    """

    # Task information
    task_id: str = Field(default="", description="Unique task identifier")
    task_description: str = Field(default="", description="Description of the vulnerability and what to fix")
    vulnerability_type: str = Field(default="", description="Vulnerability category, e.g. XSS, SQLi, SSRF")
    cwe_id: str = Field(default="", description="Common Weakness Enumeration ID, e.g. CWE-79")
    vulnerable_code: str = Field(default="", description="The original vulnerable source code to fix")
    function_signature: str = Field(default="", description="Expected function signature")
    difficulty: str = Field(default="", description="easy, medium, or hard")

    # Execution feedback
    stdout: str = Field(default="", description="Captured stdout")
    stderr: str = Field(default="", description="Captured stderr")

    # Dual grading results
    test_summary: str = Field(default="", description="Human-readable summary")
    functional_tests_passed: int = Field(default=0, description="Functional tests passed")
    functional_tests_total: int = Field(default=0, description="Total functional tests")
    security_tests_passed: int = Field(default=0, description="Security/exploit tests passed")
    security_tests_total: int = Field(default=0, description="Total security tests")
    functional_score: float = Field(default=0.01, description="Functional score in (0, 1)")
    security_score: float = Field(default=0.01, description="Security score in (0, 1)")
    test_feedback: List[str] = Field(default_factory=list, description="Per-test feedback")

    # Episode progress
    attempts_remaining: int = Field(default=0, description="Steps remaining")
    attempts_used: int = Field(default=0, description="Steps taken")

    @model_validator(mode="after")
    def clamp_all_scores(self) -> "AppSecObservation":
        """Ensure all score fields are strictly in (0, 1) at model level.
        
        Uses __dict__ to bypass validate_assignment=True on the base
        Observation class, which would otherwise cause infinite recursion.
        """
        self.__dict__["reward"] = _clamp_score(self.reward)
        self.__dict__["functional_score"] = _clamp_score(self.functional_score)
        self.__dict__["security_score"] = _clamp_score(self.security_score)
        return self


class AppSecState(State):
    """Internal environment state."""

    task_id: str = Field(default="", description="Current task identifier")
    difficulty: str = Field(default="", description="Current task difficulty")
    max_attempts: int = Field(default=10, description="Max attempts per episode")
    best_score: float = Field(default=0.01, description="Best reward this episode")

    @model_validator(mode="after")
    def clamp_best_score(self) -> "AppSecState":
        """Ensure best_score is strictly in (0, 1)."""
        self.__dict__["best_score"] = _clamp_score(self.best_score)
        return self

