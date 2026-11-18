# Development

How to run the tests and the checks that CI runs.

## Dev container (recommended)

The dev container has the same tool versions for everyone: Python 3.12, PowerShell 7.6 with Pester 5.9, the Azure CLI 2.91, and Node.js. `.devcontainer/Dockerfile` pins the versions and checks the PowerShell download against a SHA-256 checksum. It works on Intel and Apple silicon. You need Docker.

- VS Code: Open the folder. Then select **Reopen in Container**. The container runs `make check` when it is created.
- Without VS Code:

  ```bash
  make docker-check   # build the image, then run all linters and tests in it
  make docker-shell   # a shell in the container; this folder is /workspace
  ```

  Without `make` (for example in PowerShell on Windows):

  ```powershell
  docker build -f .devcontainer/Dockerfile -t m365-ato-monitor-dev .
  docker run --rm -it -v "${PWD}:/workspace" m365-ato-monitor-dev make check
  ```

The container is for development and tests. Install the monitor from your computer or from Azure Cloud Shell. In a container, `az login` must use the device code flow (`az login --use-device-code`). Conditional Access can block this flow. Also, this monitor reports device code sign-ins.

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
| Dependency audit | `pip-audit` on `function/requirements.txt` (the newest versions that a deploy installs) |
| PowerShell (install.ps1) | PowerShell parser for the `.ps1` files; Pester tests of `install.ps1` with a fake `az` |
| Workflow security (zizmor) | Injection, unpinned actions, and token permissions in `.github` |

A second workflow (`.github/workflows/devcontainer.yml`) builds the dev container and runs `make check` in it. It runs when the container or its inputs change, and on the 1st of each month. As a result, CI finds early a pinned download that changes or disappears. Dependabot updates the base image.

## Releases

To release, raise `VERSION` in `function/version.py` (`MAJOR.MINOR.PATCH`) in a commit to `main`. The release workflow (`.github/workflows/release.yml`) runs CI, then tags the commit `v<VERSION>` and publishes a GitHub release with generated notes. The workflow skips a version that already has a release.

Installed monitors check the latest release once a day. They show "Update available" in the management UI and the weekly report. A person then runs `./install.ps1 -Update`. If an update needs more than `-Update` (for example a step that the person must do by hand), say so in the release notes.

For the repository settings to apply, see [Security: CI](SECURITY.md#ci). To add a detection, see [AGENTS.md](../AGENTS.md#add-a-detection).
