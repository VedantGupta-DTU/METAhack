"""
Data models for AppSecEnv — Application Security Vulnerability Auto-Patcher.

The agent receives vulnerable code snippets and must rewrite them to fix
security vulnerabilities without breaking business logic. Graded via
dual testing: functional correctness + exploit prevention.
"""

from typing import Dict, List, Optional

from openenv.core.env_server.types import Action, Observation, State
from pydantic import Field


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
    functional_score: float = Field(default=0.0, description="Functional score 0.0-1.0")
    security_score: float = Field(default=0.0, description="Security score 0.0-1.0")
    test_feedback: List[str] = Field(default_factory=list, description="Per-test feedback")

    # Episode progress
    attempts_remaining: int = Field(default=0, description="Steps remaining")
    attempts_used: int = Field(default=0, description="Steps taken")


class AppSecState(State):
    """Internal environment state."""

    task_id: str = Field(default="", description="Current task identifier")
    difficulty: str = Field(default="", description="Current task difficulty")
    max_attempts: int = Field(default=10, description="Max attempts per episode")
    best_score: float = Field(default=0.0, description="Best reward this episode")
