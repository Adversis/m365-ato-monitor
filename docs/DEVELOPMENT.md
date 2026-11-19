# Development

How to run the tests and the checks that CI runs.

## Dev container (recommended)

The dev container pins Python, PowerShell, Pester, Azure CLI, and Node.js. It requires Docker.

- In VS Code, open the repository. Select **Reopen in Container**.
- From a terminal, run `make docker-check` to build the image and run the checks. Use `make docker-shell` for a shell.
- Without `make` on your host, run these Docker commands:

  ```powershell
  docker build -f .devcontainer/Dockerfile -t m365-ato-monitor-dev .
  docker run --rm -v "${PWD}:/workspace" m365-ato-monitor-dev make check
  ```

Install the monitor from your computer or Azure Cloud Shell.

## Commands

```bash
make check          # all linters and tests: what CI runs
make setup          # without the container: create the venv and install dependencies (Python 3.12)
make test           # run the offline Python tests (no Azure access)
make test-install   # run the Pester tests of install.ps1 with a fake az (no Azure access)
make lint           # check Python, JavaScript, and PowerShell (pyflakes if installed)
make dev            # run the function locally (needs Azure Functions Core Tools and credentials)
make install        # install or repair the monitor in Azure (./install.ps1)
make deploy         # deploy the code of this folder (./install.ps1 -Update)
make verify         # check the installed monitor (./install.ps1 -Verify)
make uninstall      # remove the monitor from Azure (./install.ps1 -Uninstall)
```

CI (`.github/workflows/ci.yml`) runs on each pull request, on each push to `main`, and on the 1st of each month. It has no Azure credentials and does not deploy.

| Job | Checks |
|---|---|
| Python tests and lint | `pytest`, `py_compile`, pyflakes, `node --check` (Python 3.12, as in Azure) |
| Dependency audit | `pip-audit` on `function/requirements.txt` |
| Static analysis (bandit) | Python security checks |
| PowerShell (install.ps1) | PowerShell parser for the `.ps1` files; Pester tests of `install.ps1` with a fake `az` |
| Workflow security (zizmor) | Injection, unpinned actions, and token permissions in `.github` |

A second workflow (`.github/workflows/devcontainer.yml`) builds the dev container and runs `make check` in it. It runs when the container or its inputs change, and on the 1st of each month. As a result, CI finds early a pinned download that changes or disappears. Dependabot updates the base image.

## Releases

To release, move the "Unreleased" entries in `CHANGELOG.md` under the new version, and raise `VERSION` in `function/version.py` (`MAJOR.MINOR.PATCH`) in the same commit to `main`. The release workflow (`.github/workflows/release.yml`) runs CI, then tags the commit `v<VERSION>` and publishes a GitHub release with generated notes. The workflow skips a version that already has a release.

Installed monitors check the latest release once a day. They show "Update available" in the management UI and the weekly report. A person then runs `./install.ps1 -Update`. If an update needs more than `-Update` (for example a step that the person must do by hand), say so in the release notes.

For the repository settings to apply, see [Security: CI](SECURITY.md#ci). To add a detection, see [AGENTS.md](../AGENTS.md#add-a-detection).
