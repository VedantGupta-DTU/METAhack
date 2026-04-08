"""AppSecEnv Client — connects to a running AppSecEnv server."""

from typing import Dict
from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from .models import AppSecAction, AppSecObservation, AppSecState


class AppSecEnv(EnvClient[AppSecAction, AppSecObservation, AppSecState]):
    """Client for AppSecEnv."""

    def _step_payload(self, action: AppSecAction) -> Dict:
        return {"code": action.code}

    def _parse_result(self, payload: Dict) -> StepResult[AppSecObservation]:
        obs_data = payload.get("observation", {})
        observation = AppSecObservation(
            task_id=obs_data.get("task_id", ""),
            task_description=obs_data.get("task_description", ""),
            vulnerability_type=obs_data.get("vulnerability_type", ""),
            cwe_id=obs_data.get("cwe_id", ""),
            vulnerable_code=obs_data.get("vulnerable_code", ""),
            function_signature=obs_data.get("function_signature", ""),
            difficulty=obs_data.get("difficulty", ""),
            stdout=obs_data.get("stdout", ""),
            stderr=obs_data.get("stderr", ""),
            test_summary=obs_data.get("test_summary", ""),
            functional_tests_passed=obs_data.get("functional_tests_passed", 0),
            functional_tests_total=obs_data.get("functional_tests_total", 0),
            security_tests_passed=obs_data.get("security_tests_passed", 0),
            security_tests_total=obs_data.get("security_tests_total", 0),
            functional_score=obs_data.get("functional_score", 0.0),
            security_score=obs_data.get("security_score", 0.0),
            test_feedback=obs_data.get("test_feedback", []),
            attempts_remaining=obs_data.get("attempts_remaining", 0),
            attempts_used=obs_data.get("attempts_used", 0),
            done=payload.get("done", False),
            reward=payload.get("reward"),
            metadata=obs_data.get("metadata", {}),
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> AppSecState:
        return AppSecState(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
            task_id=payload.get("task_id", ""),
            difficulty=payload.get("difficulty", ""),
            max_attempts=payload.get("max_attempts", 10),
            best_score=payload.get("best_score", 0.0),
        )
