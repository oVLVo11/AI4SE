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

Start the local WebUI in normal local mode:

```powershell
pyquality serve --host 127.0.0.1 --port 8000
```

For a deterministic credential-free public-mock WebUI, run:

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
python -m pip install dist\pyquality_harness-0.1.0-py3-none-any.whl
```

Build and run the public-mock container locally:

```powershell
docker build -t pyquality-harness .
docker run --rm -p 8000:8000 pyquality-harness
```

### Render-compatible deployment

The reviewed Docker service is publicly available at https://ai4se.onrender.com. It deploys the supplied Dockerfile unchanged and starts only deterministic public mock mode. The free-tier service can sleep between visits and provides no production availability guarantee.

No credentials, provider configuration, database, or persistent disk are attached to this free-tier public mock service.

### Release evidence

Public repository: https://github.com/oVLVo11/AI4SE.git

Initial verified CI run: https://github.com/oVLVo11/AI4SE/actions/runs/30544072702

Commit: `89544fc9d295fdbe0d6d20fd1ffc202d5238144f`; conclusion: `success`.

Final GitHub Actions run https://github.com/oVLVo11/AI4SE/actions/runs/30567593776 completed with conclusion `success` for `82958a82dfc12b171691042c012c5279ae639dea`; job https://github.com/oVLVo11/AI4SE/actions/runs/30567593776/job/90955887900 reported pytest, Ruff, package, and Docker successful.

Render service: https://ai4se.onrender.com; deployed commit: `82958a82dfc12b171691042c012c5279ae639dea`; deploy ID: `dep-d9loso4s728c739i80rg`.

The Render deploy SHA and deploy ID are user-supplied dashboard evidence. The controller independently verified GitHub CI through the GitHub API. Hosted acceptance was independently verified by the controller through the real HTTP CSRF form.

At `2026-07-30 17:50:41 GMT`, the controller independently repeated the real hosted CSRF flow and received HTTP 200 at https://ai4se.onrender.com/tasks/public-demo with terminal `SUCCEEDED` and zero remaining rounds.

Guardrail: `outside action denied`.

Feedback: `assertion`.

Progress: `read_file -> apply_patch -> apply_patch -> finish`.

The public response contained no forbidden local or temporary paths, `LEAK` sentinels, prompt/source/patch bodies, provider key, credential prompt, traceback, or server error.

Task results are process-local and may return HTTP 404 after a restart or free-tier sleep until the bundled scenario is rerun.

Local Docker CLI remains unavailable; no local Docker success is claimed.

Task 13 implementation tasks are reviewed; final broad review pending.

These tracked records cover verified pre-audit commit `82958a82dfc12b171691042c012c5279ae639dea` and do not claim CI or deployment success for the later final-audit commit; post-commit remote verification belongs only in ignored evidence.

## Credential Security

Public mock mode does not require credentials. For local mode, prefer keyring-first storage. `PYQUALITY_API_KEY` is a warned plaintext fallback; do not place it, provider credentials, API keys, tokens, or passwords in source files, container build arguments, environment files committed to Git, or command history.

## Project Structure

- `src/pyquality/` contains the package, CLI, web templates, and deterministic demo fixture.
- `tests/` contains automated unit, component, end-to-end, security, web, and distribution checks.
- `pyproject.toml` defines package metadata, build settings, and development dependencies.

## Safety Boundaries

The included public mock mode is intended for demonstrations and repeatable checks. Local mode keeps state in local SQLite and audit files. Repository confinement controls which paths the tool accepts; it is not an operating-system sandbox. Review any configuration that could access external services before using it, and keep local runtime data outside distributable artifacts.

## Known Limitations

The hosted demonstration is mock-only, free-tier, ephemeral, and not a production service. No credentials, provider configuration, database, or persistent disk are attached to this free-tier public mock service. This repository does not provide managed credentials or a production service guarantee. Local container execution requires a locally available Docker-compatible runtime; no local Docker CLI success is claimed by the recorded release evidence.
