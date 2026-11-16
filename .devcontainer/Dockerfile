# Development container for M365 ATO Monitor.
#
# The same tool versions for every developer and for CI:
#   Python 3.12 (the Function App runtime), PowerShell 7 with Pester 5
#   (install.ps1 and its tests), the Azure CLI, Node.js (JavaScript syntax
#   check), make, git.
#
# Use it from VS Code ("Reopen in Container"), or without VS Code:
#   make docker-check     build the image, then run all linters and tests in it
#   make docker-shell     a shell in the container, with this folder at /workspace
#
# To update a pinned tool, change its ARG (and the PowerShell checksums), then
# run make docker-check. Dependabot updates the base image digest.

FROM python:3.15-slim-bookworm@sha256:96599df822d0e1c6bb700014a05c7f3c8cabc6e0f7ff3c4f9f69cee033b4b5d9

# PowerShell: https://github.com/PowerShell/PowerShell/releases (SHA-256 of the linux tar.gz files)
ARG PWSH_VERSION=7.6.9
ARG PWSH_SHA256_X64=1da6d6d6035d651f20e70ddee7c4c15ac6ab8b9fb40ee92240d91263f28a884b
ARG PWSH_SHA256_ARM64=02eb9991af447c7e7fe881acde195961afd397c40b8eb1c2b3856b84ec2d85f2
# Pester: https://www.powershellgallery.com/packages/Pester (CI uses 5.x)
ARG PESTER_VERSION=5.9.0
# Azure CLI: https://pypi.org/project/azure-cli/ (install.ps1 needs 2.60 or later)
ARG AZ_CLI_VERSION=2.91.0

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POWERSHELL_TELEMETRY_OPTOUT=1 \
    AZURE_CORE_COLLECT_TELEMETRY=false

# Tools from Debian. libicu72 is needed by PowerShell. nodejs is only for "node --check".
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git less libicu72 make nodejs \
 && rm -rf /var/lib/apt/lists/*

# PowerShell 7 for amd64 (Intel, most CI) and arm64 (Apple silicon). The download must match the checksum.
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) arch=x64; sum="$PWSH_SHA256_X64" ;; \
      arm64) arch=arm64; sum="$PWSH_SHA256_ARM64" ;; \
      *) echo "Unsupported architecture: $(dpkg --print-architecture)"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/pwsh.tar.gz \
      "https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell-${PWSH_VERSION}-linux-${arch}.tar.gz"; \
    echo "${sum}  /tmp/pwsh.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/microsoft/powershell/7; \
    tar -xzf /tmp/pwsh.tar.gz -C /opt/microsoft/powershell/7; \
    chmod +x /opt/microsoft/powershell/7/pwsh; \
    ln -s /opt/microsoft/powershell/7/pwsh /usr/local/bin/pwsh; \
    rm /tmp/pwsh.tar.gz

# Pester for all users (the container can run as any user ID).
# -TrustRepository: no prompt (a build cannot answer one). Stop at the first error.
RUN pwsh -NoLogo -NoProfile -Command \
    "\$ErrorActionPreference = 'Stop'; Install-PSResource -Name Pester -Version '${PESTER_VERSION}' -Scope AllUsers -TrustRepository -Quiet; Import-Module Pester -RequiredVersion '${PESTER_VERSION}'"

# Azure CLI in its own virtual environment, so its packages do not change the app's packages.
RUN python -m venv /opt/az \
 && /opt/az/bin/pip install "azure-cli==${AZ_CLI_VERSION}" \
 && ln -s /opt/az/bin/az /usr/local/bin/az

# The app's packages and the test tools (system Python, no venv in the container).
COPY function/requirements.txt tests/requirements-test.txt /tmp/requirements/
RUN pip install -r /tmp/requirements/requirements.txt -r /tmp/requirements/requirements-test.txt \
 && rm -rf /tmp/requirements

# A normal user for VS Code. "make docker-check" runs as your own user ID instead.
RUN useradd --create-home --uid 1000 --shell /bin/bash dev
USER dev
WORKDIR /workspace
CMD ["bash"]
