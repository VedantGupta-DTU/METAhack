"""FastAPI application for AppSecEnv."""

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:
    raise ImportError("openenv is required. Install with 'uv sync'") from e

try:
    from ..models import AppSecAction, AppSecObservation
    from .kernel_env_environment import KernelEnvironment
except (ImportError, ModuleNotFoundError):
    from models import AppSecAction, AppSecObservation
    from server.kernel_env_environment import KernelEnvironment

app = create_app(
    KernelEnvironment,
    AppSecAction,
    AppSecObservation,
    env_name="kernel_env",
    max_concurrent_envs=4,
)


def main(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
