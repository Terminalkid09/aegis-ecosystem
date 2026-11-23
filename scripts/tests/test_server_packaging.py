"""Static contracts for the complete Aegis/Kraken server packages.

These tests do not claim a package was started. They catch the packaging
mistakes that make a clean install fail: ambiguous names, a unit that silently
depends on a missing docker.service, a non-root helper, a missing Windows
edition, or an update that installs unverified bytes.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_package_scope_is_unambiguous() -> None:
    aegis = _text("packaging/server/aegis/control")
    kraken = _text("packaging/server/kraken/control")
    suite = _text("packaging/server/aegis-suite/control")

    assert aegis.startswith("Package: aegis\n")
    assert "dashboard" in aegis
    assert kraken.startswith("Package: kraken\n")
    assert "Description: Kraken" in kraken
    assert "Package: aegis-suite\n" in suite
    assert "Depends: aegis (= __VERSION__), kraken (= __VERSION__)" in suite
    assert "aegis-agent" not in suite.split("Depends:", 1)[1].split("\n", 1)[0]


def test_units_run_as_root_and_do_not_require_a_wsl_missing_docker_unit() -> None:
    for package, unit in (("aegis", "aegis"), ("kraken", "kraken")):
        text = _text(f"packaging/server/{package}/{unit}.service")
        assert "Wants=docker.service" in text
        assert "After=docker.service" in text
        assert "Requires=docker.service" not in text
        assert "User=root" in text
        assert "ExecStartPre=" in text
        assert "ExecStart=" in text
        assert "ExecStop=" in text
        assert "WantedBy=multi-user.target" in text


def test_postinst_enables_the_renamed_unit_and_protects_secrets() -> None:
    for package, unit in (("aegis", "aegis"), ("kraken", "kraken")):
        text = _text(f"packaging/server/{package}/postinst")
        assert f"systemctl enable {unit}.service" in text
        assert f"systemctl is-enabled --quiet {unit}.service" in text
        assert "AEGIS_PACKAGE_SKIP_START" in text
        assert "chmod 0600" in text
        assert "chown root:root" in text
        assert "docker info" in text
        assert "images.ok" in text


def test_suite_wires_shared_network_and_cross_stack_secrets() -> None:
    suite = _text("packaging/server/aegis-suite/wire.sh")
    postinst = _text("packaging/server/aegis-suite/postinst")
    root = _text("docker-compose.yml")
    kraken = _text("packaging/server/kraken/docker-compose.yml")

    assert "aegis_shared" in root
    assert "aegis_shared" in kraken
    assert "suite-wire.sh" in postinst
    assert "KRAKEN_SSO_SECRET" in suite
    assert "KRAKEN_INGEST_SECRET" in suite
    assert "KRAKEN_INGEST_URL http://aegis-brain:8000" in suite
    assert "KRAKEN_INGEST_KEY" in suite
    assert "KRAKEN_PUBLIC_BASE_PATH /kraken" in suite
    assert "aegis-suite/postinst" in _text("scripts/build-server-deb.sh")
    assert "aegis-suite/wire.sh" in _text("scripts/build-server-deb.sh")
    assert "suite-wire.sh" in _text("packaging/server/aegis/postinst")
    assert "suite-wire.sh" in _text("packaging/server/kraken/postinst")


def test_shared_ak_cli_is_installed_without_a_package_file_conflict() -> None:
    cli = _text("packaging/server/ak.sh")
    build = _text("scripts/build-server-deb.sh")
    aegis_postinst = _text("packaging/server/aegis/postinst")
    kraken_postinst = _text("packaging/server/kraken/postinst")
    aegis_prerm = _text("packaging/server/aegis/prerm")
    kraken_prerm = _text("packaging/server/kraken/prerm")
    readme = _text("packaging/server/README.md")

    assert "Usage:" in cli
    assert "ak <command> [component]" in cli
    assert "systemctl start --no-block" in cli
    assert "docker compose" in cli
    assert "ak doctor" in cli
    assert "__VERSION__" in cli
    assert "$(require_components" not in cli
    assert "unknown component:" in cli
    assert "cmd_update" in cli
    assert "--allow-downgrade" in cli
    assert "SHA-256 mismatch" in cli
    assert "latest_version" in cli

    assert "packaging/server/ak.sh" in build
    assert "ak-aegis" in build
    assert "ak-kraken" in build
    assert "ak-aegis 20" in aegis_postinst
    assert "ak-kraken 10" in kraken_postinst
    assert "update-alternatives --remove ak /usr/local/lib/aegis/ak-aegis" in aegis_prerm
    assert "update-alternatives --remove ak /usr/local/lib/aegis/ak-kraken" in kraken_prerm
    assert "/usr/local/bin/ak" in aegis_postinst
    assert "/usr/local/bin/ak" in kraken_postinst
    assert "ak status" in readme
    assert "ak configure" in cli
    assert "ak update" in cli
    assert "AEGIS_UI_PORT" in _text("docker-compose.yml")
    assert "AEGIS_UI_PORT" in _text("packaging/server/aegis/server-env.sh")
    assert "ak_find_free_ui_port" in _text("packaging/server/aegis/ui-port.sh")
    assert "packaging/server/aegis/ui-port.sh" in build
    assert "packaging/server/aegis/ensure-ui-port.sh" in build
    assert "packaging/server/aegis/config" in build
    assert "ensure-ui-port.sh" in _text("packaging/server/aegis/build-server.sh")
    assert "help logs" in _text("scripts/tests/ak_smoke.sh")
    assert "packaging/server/aegis/templates" in build
    assert "debconf" in _text("packaging/server/aegis/control")
    assert "db_get aegis/domain" in aegis_postinst
    assert "AEGIS_UI_PORT" in aegis_postinst


def test_windows_server_package_matrix_is_complete_and_edition_aware() -> None:
    wxs = _text("packaging/windows/server/aegis-server.wxs")
    build = _text("scripts/build-server-msi.ps1")
    config = _text("packaging/windows/server/configure-server.ps1")
    cli = _text("packaging/windows/server/ak.ps1")
    readme = _text("packaging/server/README.md")
    docs = _text("docs/AK_CLI.md")

    assert "AegisConfigDlg" in wxs
    assert 'Order="99"' in wxs
    assert "HAS_AEGIS" in wxs
    assert "AEGIS_DOMAIN" in wxs
    assert "ACME_EMAIL" in wxs
    assert "AEGIS_UI_PORT" in wxs
    assert "AkPath" in wxs
    assert "ServerSettings" in wxs
    assert "ComponentGroupRef Id=\"Payload\"" in wxs
    assert "AllowDowngrades=\"yes\"" in wxs

    assert "ValidateSet(\"aegis\", \"kraken\", \"suite\")" in build
    assert '"aegis-server"' in build or "stem = \"aegis-server\"" in build
    assert '"kraken-server"' in build or "stem = \"kraken-server\"" in build
    assert '"aegis-suite"' in build or "stem = \"aegis-suite\"" in build
    assert "$stem-$Version-x64.msi" in build
    assert "Build-AegisPayload" in build
    assert "Build-KrakenPayload" in build
    assert "services\\kraken" in build
    assert "Copy-CommonPayload" in build
    assert "configure-server.ps1" in build
    assert "RELEASE_POLICY.md" in build

    assert "param(" in config
    assert "ValidateSet(\"aegis\", \"kraken\", \"suite\")" in config
    assert "kraken.env" in config
    assert "KRAKEN_DB_PASSWORD" in config
    assert "Assert-Domain" in config
    assert "ACME email is required for a public FQDN" in config
    assert "S-1-5-32-544" in config

    assert "__EDITION__" in cli
    assert "__REGISTRY_NAME__" in cli
    assert "Cmd-Update" in cli
    assert "Get-LatestVersion" in cli
    assert "Get-EditionAsset" in cli
    assert "SHA-256 mismatch" in cli
    assert "AllowDowngrades" in wxs
    assert "Assert-Admin" in cli
    assert "Main -Arguments $args" in cli
    assert "aegis-server-<version>-x64.msi" in readme
    assert "kraken-server-<version>-x64.msi" in readme
    assert "aegis-suite-<version>-x64.msi" in readme
    assert "aegis-suite-<version>-x64.msi" in docs
    assert "pre-login" in docs
    assert "ak update" in docs


def test_release_update_policy_is_explicit_and_fail_closed() -> None:
    policy = _text("docs/RELEASE_POLICY.md")
    linux = _text("packaging/server/ak.sh")
    windows = _text("packaging/windows/server/ak.ps1")

    assert "4.3.x" in policy and "Current stable" in policy
    assert "4.2.x" in policy and "Previous minor" in policy
    assert "4.1.x" in policy and "End of life" in policy
    assert "verified database backup" in policy
    assert "Published Git tags and GitHub Releases are **immutable**" in policy
    assert "does not enable itself" in policy

    assert "cmd_update" in linux
    assert "sha256sum" in linux
    assert "latest_version" in linux
    assert "--allow-downgrade" in linux
    assert "RELEASE_POLICY" in linux or "release-policy" in linux
    assert "Cmd-Update" in windows
    assert "Get-FileHash" in windows
    assert "--allow-downgrade" in windows
    assert "RELEASE_POLICY" in windows


def test_build_script_emits_both_stacks_and_the_one_file_bundle() -> None:
    text = _text("scripts/build-server-deb.sh")
    assert "aegis_${VERSION}_amd64.deb" in text
    assert "kraken_${VERSION}_amd64.deb" in text
    assert "aegis-suite_${VERSION}_all.deb" in text
    assert "aegis-suite-${VERSION}.tar.gz" in text
    assert "SIGNING_MODE:-self-signed" in text
    assert "aegis-pilot-signing-key.asc" in text
    assert "--exclude=.ruff_cache" in text
    assert "--exclude=.pytest_cache" in text
    assert "apt-get install -y" in text
    assert "aegis-suite_[0-9]*_all.deb" in text
    assert "ak url" in text
    assert "does not install them" in _text("packaging/server/README.md")
    assert "ui-port.sh" in _text("packaging/server/aegis/server-env.sh")
    assert "AEGIS_UI_PORT" in _text("docs/PACKAGING.md")
    assert "AK_CLI.md" in _text("README.md")


def test_start_wait_doctor_resources_and_release_publication() -> None:
    linux = _text("packaging/server/ak.sh")
    windows = _text("packaging/windows/server/ak.ps1")
    cli_docs = _text("docs/AK_CLI.md")
    workflow = _text(".github/workflows/packaging.yml")
    packaging = _text("docs/PACKAGING.md")

    # --wait starts the unit synchronously, then polls Compose health.
    assert "wait_for_component" in linux
    assert "ps --status running" in linux
    assert "--timeout must be a number of seconds" in linux
    assert "defaults to 300" in cli_docs
    assert "--no-wait" in windows
    assert "function Wait-Component" in windows
    assert "status=running" in windows
    assert "health: starting" in windows

    # Doctor reports the memory budget and the WSL ceiling, not a guess.
    assert "Resources:" in linux
    assert "Docker engine limit" in linux
    assert "autoMemoryReclaim" in linux
    assert "WSL ceiling" in windows

    # An update must not block on debconf or conffile prompts.
    assert 'DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"' in linux
    assert "--force-confdef" in linux
    assert "--force-confold" in linux

    # Only ICE61 is suppressed: the downgrade is intentional and documented.
    assert "-sice ICE61" in workflow
    assert "AllowDowngrades" in packaging or "ICE61" in packaging

    # The release job attaches packages to the release created by ci.yml and
    # never overwrites a published asset.
    assert "release_assets" in workflow
    assert "gh release upload" in workflow
    assert "already has $name" in workflow
    assert "pattern:" in workflow
