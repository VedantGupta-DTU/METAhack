"""
Sandboxed Python code executor for AppSecEnv with dual grading.

Executes agent-submitted code in a subprocess and grades it against:
  - Functional tests: normal inputs must produce correct output
  - Exploit tests: malicious inputs must be blocked (exception or safe output)
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class TestResult:
    passed: bool = False
    description: str = ""
    expected: Any = None
    actual: Any = None
    error: str = ""
    test_type: str = "functional"


@dataclass
class ExecutionResult:
    stdout: str = ""
    stderr: str = ""
    success: bool = False
    timed_out: bool = False
    error_type: str = ""
    test_results: List[TestResult] = field(default_factory=list)
    tests_passed: int = 0
    tests_total: int = 0
    functional_passed: int = 0
    functional_total: int = 0
    security_passed: int = 0
    security_total: int = 0


def _build_test_harness(
    agent_code: str,
    function_name: str,
    test_cases_json: str,
) -> str:
    """Build a Python script that runs agent code against dual test cases."""
    # Escape the agent code for safe embedding
    safe_code = agent_code.replace('\\', '\\\\').replace('"""', "'''")
    return textwrap.dedent(f'''\
import json
import sys
import traceback
import random

# ---- Agent code ----
try:
    exec("""
{safe_code}
""")
    code_error = None
except Exception as e:
    code_error = dict(type=type(e).__name__, message=str(e))

# ---- Run test cases ----
test_cases = json.loads('{test_cases_json}')
results = []

if code_error:
    for tc in test_cases:
        results.append(dict(
            passed=False,
            description=tc["description"],
            expected=tc.get("expected_output"),
            actual=None,
            error=f"{{code_error['type']}}: {{code_error['message']}}",
            test_type=tc.get("test_type", "functional"),
        ))
else:
    fn = locals().get("{function_name}") or globals().get("{function_name}")
    if fn is None:
        for tc in test_cases:
            results.append(dict(
                passed=False,
                description=tc["description"],
                expected=tc.get("expected_output"),
                actual=None,
                error="Function '{function_name}' not defined",
                test_type=tc.get("test_type", "functional"),
            ))
    else:
        for tc in test_cases:
            test_type = tc.get("test_type", "functional")
            exploit_payload = tc.get("exploit_payload", "")
            try:
                args = tuple(tc.get("input_args", []))
                kwargs = tc.get("input_kwargs", {{}})

                if test_type == "exploit":
                    # For exploit tests: exception = blocked = PASS
                    try:
                        actual = fn(*args, **kwargs)
                        # Function didn't raise — check if output is safe
                        output_str = str(actual)
                        if exploit_payload and exploit_payload in output_str:
                            # Dangerous payload found in output!
                            results.append(dict(
                                passed=False,
                                description=tc["description"],
                                expected="BLOCKED",
                                actual=actual,
                                error=f"Security: Output contains exploit payload",
                                test_type="exploit",
                            ))
                        else:
                            # Output is safe (payload not present)
                            results.append(dict(
                                passed=True,
                                description=tc["description"],
                                expected="BLOCKED or SAFE",
                                actual=actual,
                                error="",
                                test_type="exploit",
                            ))
                    except Exception:
                        # Exception raised = exploit was blocked = PASS
                        results.append(dict(
                            passed=True,
                            description=tc["description"],
                            expected="BLOCKED",
                            actual="Exception raised (exploit blocked)",
                            error="",
                            test_type="exploit",
                        ))

                elif tc["description"].startswith("Token length"):
                    # Special handling for token length checks (e5)
                    actual = fn(*args, **kwargs)
                    expected_len = tc["expected_output"]
                    passed = isinstance(actual, str) and len(actual) == expected_len
                    all_hex = all(c in '0123456789abcdef' for c in actual.lower()) if isinstance(actual, str) else False
                    results.append(dict(
                        passed=passed and all_hex,
                        description=tc["description"],
                        expected=f"hex string of length {{expected_len}}",
                        actual=f"len={{len(actual) if isinstance(actual, str) else 'N/A'}}, hex={{all_hex}}",
                        error="" if (passed and all_hex) else f"Expected hex string of length {{expected_len}}",
                        test_type="functional",
                    ))

                elif tc["description"].startswith("Token not predictable"):
                    # Special: test that random.seed doesn't make output predictable
                    random.seed(42)
                    t1 = fn(*args, **kwargs)
                    random.seed(42)
                    t2 = fn(*args, **kwargs)
                    # If using secrets, t1 != t2 despite same random seed
                    passed = (t1 != t2)
                    results.append(dict(
                        passed=passed,
                        description=tc["description"],
                        expected="Unpredictable tokens",
                        actual=f"t1=={{t1[:8]}}..., t2=={{t2[:8]}}..., same={{t1==t2}}",
                        error="" if passed else "Tokens are predictable (using random instead of secrets)",
                        test_type="exploit",
                    ))

                else:
                    # Standard functional test
                    actual = fn(*args, **kwargs)
                    passed = (actual == tc["expected_output"])
                    results.append(dict(
                        passed=passed,
                        description=tc["description"],
                        expected=tc["expected_output"],
                        actual=actual,
                        error="" if passed else f"Expected {{tc['expected_output']!r}}, got {{actual!r}}",
                        test_type="functional",
                    ))

            except Exception as e:
                results.append(dict(
                    passed=False,
                    description=tc["description"],
                    expected=tc.get("expected_output"),
                    actual=None,
                    error=f"{{type(e).__name__}}: {{e}}",
                    test_type=test_type,
                ))

# Output structured results
print("__APPSEC_RESULTS__")
print(json.dumps(results))
''')


def execute_code(
    agent_code: str,
    function_name: str,
    test_cases: List[Dict[str, Any]],
    timeout_s: float = 5.0,
) -> ExecutionResult:
    """Execute agent code in a subprocess and run dual test cases."""
    test_cases_json = json.dumps(test_cases).replace("'", "\\'")
    script = _build_test_harness(agent_code, function_name, test_cases_json)

    result = ExecutionResult(tests_total=len(test_cases))
    tmp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir=None
        ) as f:
            f.write(script)
            tmp_path = f.name

        proc = subprocess.run(
            [sys.executable, tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )

        raw_stdout = proc.stdout
        if "__APPSEC_RESULTS__" in raw_stdout:
            parts = raw_stdout.split("__APPSEC_RESULTS__", 1)
            result.stdout = parts[0].strip()
            try:
                results_json = json.loads(parts[1].strip())
                for r in results_json:
                    tr = TestResult(
                        passed=r["passed"],
                        description=r["description"],
                        expected=r.get("expected"),
                        actual=r.get("actual"),
                        error=r.get("error", ""),
                        test_type=r.get("test_type", "functional"),
                    )
                    result.test_results.append(tr)

                    if tr.test_type == "exploit":
                        result.security_total += 1
                        if tr.passed:
                            result.security_passed += 1
                    else:
                        result.functional_total += 1
                        if tr.passed:
                            result.functional_passed += 1

                result.tests_passed = sum(1 for r in result.test_results if r.passed)
                result.success = True
            except (json.JSONDecodeError, KeyError, IndexError):
                result.stderr = proc.stderr
                result.success = False
                result.error_type = "OutputParseError"
        else:
            result.stdout = raw_stdout.strip()
            result.stderr = proc.stderr.strip()
            if proc.returncode != 0:
                result.success = False
                for line in result.stderr.splitlines():
                    if "Error" in line:
                        result.error_type = line.split(":")[0].strip().split(".")[-1]
                        break
            else:
                result.success = True

    except subprocess.TimeoutExpired:
        result.timed_out = True
        result.stderr = f"Execution timed out after {timeout_s}s"
        result.error_type = "TimeoutError"

    except Exception as e:
        result.stderr = f"Executor error: {type(e).__name__}: {e}"
        result.error_type = type(e).__name__

    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass

    return result
