# PyQuality Harness

PyQuality Harness is a local quality-workflow exercise with a deterministic public mock mode for demonstrations.

## Installation

Python 3.12 or newer is required. Create an environment, then install the development tools:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Running

Run the deterministic local demonstration:

```powershell
pyquality demo --json
```

Start the local public-mock server:

```powershell
pyquality serve --host 127.0.0.1 --port 8000 --public-mock
```

## Distribution

Build distributable archives locally:

```powershell
python -m build --no-isolation
```

Install the generated wheel in a fresh environment with `python -m pip install dist\*.whl`.

## Credential Security

Public mock mode does not require credentials. Do not place provider credentials, API keys, tokens, or passwords in source files, container build arguments, environment files committed to Git, or command history. Use your local secret-management process for any non-mock configuration.

## Project Structure

- `src/pyquality/` contains the package, CLI, web templates, and deterministic demo fixture.
- `tests/` contains automated unit, component, end-to-end, security, web, and distribution checks.
- `pyproject.toml` defines package metadata, build settings, and development dependencies.

## Safety Boundaries

The included public mock mode is intended for local demonstrations and repeatable checks. Review any configuration that could access external services before using it, and keep local runtime data outside distributable artifacts.

## Known Limitations

This repository does not provide hosted deployment, managed credentials, or a production service guarantee. Container execution requires a locally available Docker-compatible runtime.
