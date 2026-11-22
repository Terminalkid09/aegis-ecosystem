#!/usr/bin/env bash
# Build an RPM for the unified agent. Production signing is a separate release
# step: sign the resulting RPM with the operator's GPG/RPM key, never a test key.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-4.3.0}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
AGENT_BIN="${AGENT_BIN:-$ROOT/.tmp/packaging/aegis-agent-linux}"

if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "rpmbuild not found. Install rpm-build/rpm on the packaging host." >&2
    exit 2
fi
if [ ! -f "$AGENT_BIN" ]; then
    mkdir -p "$(dirname "$AGENT_BIN")"
    (cd "$ROOT/aegis-agent" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -trimpath -ldflags "-s -w -X main.buildVersion=$VERSION" \
        -o "$AGENT_BIN" ./cmd/aegis-agent)
fi

TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
install -m 0755 "$AGENT_BIN" "$TOP/SOURCES/aegis-agent"
install -m 0644 "$ROOT/aegis-agent/packaging/linux/lib/systemd/system/aegis-agent.service" \
    "$TOP/SOURCES/aegis-agent.service"
install -m 0644 "$ROOT/aegis-agent/packaging/linux/etc/aegis-agent/aegis-agent.env.example" \
    "$TOP/SOURCES/aegis-agent.env.example"
if [ -f "${EBPF_COLLECTOR:-$ROOT/aegis-ebpf/aegis-collector}" ]; then
    install -m 0755 "${EBPF_COLLECTOR:-$ROOT/aegis-ebpf/aegis-collector}" \
        "$TOP/SOURCES/aegis-collector"
fi
if [ -f "${EBPF_OBJ:-$ROOT/aegis-ebpf/aegis_exec.bpf.o}" ]; then
    install -m 0644 "${EBPF_OBJ:-$ROOT/aegis-ebpf/aegis_exec.bpf.o}" \
        "$TOP/SOURCES/aegis_exec.bpf.o"
fi

SPEC="$TOP/SPECS/aegis-agent.spec"
cat > "$SPEC" <<EOF
Name:           aegis-agent
Version:        $VERSION
Release:        1%{?dist}
Summary:        Aegis unified endpoint and sensor agent
License:        AGPL-3.0-only
URL:            https://github.com/Terminalkid09/aegis-ecosystem
BuildArch:      x86_64
Requires:       ca-certificates
Source0:        aegis-agent
Source1:        aegis-agent.service
Source2:        aegis-agent.env.example
%{?ebpf_collector_source:%{expand:Source3: %{ebpf_collector_source}}}
%{?ebpf_obj_source:%{expand:Source4: %{ebpf_obj_source}}}

%description
One binary with explicit full, sensor and endpoint modes. The RPM installs the
systemd unit and leaves enrollment token provisioning to the operator or MDM.
It does not start the service automatically.

%prep
%build
%install
rm -rf %{buildroot}
install -d %{buildroot}/usr/local/bin
install -d %{buildroot}/usr/local/lib/aegis-agent
install -d %{buildroot}/lib/systemd/system
install -d %{buildroot}/etc/aegis-agent
install -m 0755 %{_sourcedir}/aegis-agent %{buildroot}/usr/local/bin/aegis-agent
install -m 0644 %{_sourcedir}/aegis-agent.service %{buildroot}/lib/systemd/system/aegis-agent.service
install -m 0644 %{_sourcedir}/aegis-agent.env.example %{buildroot}/etc/aegis-agent/aegis-agent.env.example
if [ -f %{_sourcedir}/aegis-collector ]; then
    install -m 0755 %{_sourcedir}/aegis-collector %{buildroot}/usr/local/lib/aegis-agent/aegis-collector
fi
if [ -f %{_sourcedir}/aegis_exec.bpf.o ]; then
    install -m 0644 %{_sourcedir}/aegis_exec.bpf.o %{buildroot}/usr/local/lib/aegis-agent/aegis_exec.bpf.o
fi

%post
install -d -m 0700 /var/lib/aegis-agent
install -d -m 0750 /etc/aegis-agent
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable aegis-agent.service
    systemctl is-enabled --quiet aegis-agent.service
fi

%preun
if [ "\$1" = "0" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop aegis-agent.service || true
    systemctl disable aegis-agent.service || true
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

%files
%defattr(-,root,root,-)
/usr/local/bin/aegis-agent
/lib/systemd/system/aegis-agent.service
%config(noreplace) /etc/aegis-agent/aegis-agent.env.example
%dir /usr/local/lib/aegis-agent
%if %{?_with_ebpf_collector:1}%{!?_with_ebpf_collector:0}
/usr/local/lib/aegis-agent/aegis-collector
%endif
%if %{?_with_ebpf_obj:1}%{!?_with_ebpf_obj:0}
/usr/local/lib/aegis-agent/aegis_exec.bpf.o
%endif
EOF

# Keep the optional helper declarations out of the spec unless the files exist.
if [ -f "$TOP/SOURCES/aegis-collector" ]; then
    RPM_EXTRA=(--define "_with_ebpf_collector 1")
else
    RPM_EXTRA=()
fi
if [ -f "$TOP/SOURCES/aegis_exec.bpf.o" ]; then
    RPM_EXTRA+=(--define "_with_ebpf_obj 1")
fi

mkdir -p "$OUT_DIR"
rpmbuild --define "_topdir $TOP" --target x86_64 "${RPM_EXTRA[@]}" -bb "$SPEC" >/tmp/aegis-rpmbuild.log
RPM_PATH="$(find "$TOP/RPMS" -type f -name 'aegis-agent-*.rpm' | head -1)"
if [ -z "$RPM_PATH" ]; then
    echo "rpmbuild did not produce an RPM" >&2
    exit 1
fi
RPM="$OUT_DIR/aegis-agent-${VERSION}-1.x86_64.rpm"
install -m 0644 "$RPM_PATH" "$RPM"
rpm -qip "$RPM" >/dev/null
rpm -qlp "$RPM" >/dev/null
(cd "$OUT_DIR" && sha256sum "$(basename "$RPM")" > "$(basename "$RPM").sha256")
echo "RPM: $RPM"
echo "SHA256: $(cut -d' ' -f1 "$RPM.sha256")"
