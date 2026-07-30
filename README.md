# PyQuality Harness

PyQuality Harness is a local quality-workflow exercise with a deterministic public mock mode for demonstrations.

## Installation

Python 3.12 or newer is required. Create an environment, then install the development tools:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Credential storage is keyring-first. The `PYQUALITY_API_KEY` environment fallback is plaintext process configuration: use it only when a secure keyring is unavailable, avoid committing it, and clear it when the process ends.

## Running

Run the deterministic local demonstration:

```powershell
pyquality demo --json
```

Start the local public-mock server:

```powershell
pyquality serve --host 127.0.0.1 --port 8000 --public-mock
```

Running pytest can execute repository code. Treat a repository under test as code you are choosing to run, not as inert input.

## Distribution

Build distributable archives locally:

```powershell
python -m build --no-isolation
```

Install the generated wheel in a fresh environment with:

```powershell
python -m pip install --no-deps dist\pyquality_harness-0.1.0-py3-none-any.whl
```

Build and run the public-mock container locally:

```powershell
docker build -t pyquality-harness .
docker run --rm -p 8000:8000 pyquality-harness
```

### Render-compatible deployment

Create a Docker-based web service from this repository, configure its service port as `8000`, and deploy the supplied Dockerfile unchanged. The image starts only public mock mode, so it needs no provider credential configuration. This is a deployment procedure for a compatible platform, not a hosted service offered by this project.

## Credential Security

Public mock mode does not require credentials. For local mode, prefer keyring-first storage. `PYQUALITY_API_KEY` is a warned plaintext fallback; do not place it, provider credentials, API keys, tokens, or passwords in source files, container build arguments, environment files committed to Git, or command history.

## Project Structure

- `src/pyquality/` contains the package, CLI, web templates, and deterministic demo fixture.
- `tests/` contains automated unit, component, end-to-end, security, web, and distribution checks.
- `pyproject.toml` defines package metadata, build settings, and development dependencies.

## Safety Boundaries

The included public mock mode is intended for local demonstrations and repeatable checks. Local mode keeps state in local SQLite and audit files. Repository confinement controls which paths the tool accepts; it is not an operating-system sandbox. Review any configuration that could access external services before using it, and keep local runtime data outside distributable artifacts.

## Known Limitations

No hosted deployment is provided. This repository also does not provide managed credentials or a production service guarantee. Container execution requires a locally available Docker-compatible runtime.
