"""Deterministic shell used when the isolated sandbox is unavailable.

The honeypot must not answer every command with ``command not found``: that is
an immediate fingerprint.  This module provides a small, read-only view of a
plausible Ubuntu host.  It never executes anything on the host.  When the
broker is healthy the real sandbox is used instead.
"""
from __future__ import annotations

import posixpath
import shlex
from datetime import datetime, timezone


class FakeShell:
    def __init__(self, hostname: str = "ubuntu", user: str = "root"):
        self.hostname = hostname
        self.user = user
        self.cwd = f"/home/{user}" if user != "root" else "/root"
        self.history: list[str] = []
        self.dirs = {
            "/", "/root", "/home", "/home/ubuntu", "/tmp", "/var", "/var/www",
            "/var/www/html", "/etc", "/opt", "/srv", "/srv/backup",
        }
        self.files = {
            "/etc/hostname": hostname + "\n",
            "/etc/os-release": (
                'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
                'NAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
                'ID=ubuntu\nID_LIKE=debian\nHOME_URL="https://www.ubuntu.com/"\n'
            ),
            "/etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
            ),
            "/etc/issue": "Ubuntu 22.04.3 LTS \\n \\l\n\n",
            "/var/www/html/index.html": (
                "<!DOCTYPE html><html><head><title>Acme Portal</title></head>"
                "<body><h1>Acme Portal</h1><p>Authorized users only.</p></body></html>\n"
            ),
            "/var/www/html/robots.txt": "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n",
            "/root/.bash_history": (
                "apt update\nsystemctl status nginx\nls -la /srv/backup\n"
                "tar czf /tmp/www.tgz /var/www/html\n"
            ),
            "/srv/backup/README.txt": "Nightly backup target. Restore from vault01.\n",
            "/srv/backup/finance_q4.csv": "department,vendor,amount\nfinance,acme,1000\n",
        }
        self.files["/home/ubuntu/.bash_history"] = self.files["/root/.bash_history"]

    def prompt(self) -> str:
        short = self.cwd if self.cwd != "/" else "/"
        return f"{self.user}@{self.hostname}:{short}# "

    def execute(self, line: str) -> str:
        line = line.strip()
        if not line:
            return ""
        self.history.append(line[:512])
        try:
            parts = shlex.split(line)
        except ValueError:
            return "bash: syntax error: unexpected end of file"
        if not parts:
            return ""
        cmd, args = parts[0], parts[1:]

        if cmd in {"exit", "logout", "quit"}:
            return ""
        if cmd == "pwd":
            return self.cwd + "\n"
        if cmd == "whoami":
            return self.user + "\n"
        if cmd == "id":
            uid = "0" if self.user == "root" else "1000"
            groups = "root" if self.user == "root" else "ubuntu,sudo"
            return f"uid={uid}({self.user}) gid={uid}({self.user}) groups={uid}({groups})\n"
        if cmd == "hostname":
            return self.hostname + "\n"
        if cmd == "uname":
            if "-a" in args:
                return (
                    f"Linux {self.hostname} 5.15.0-91-generic #101-Ubuntu SMP "
                    "Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
                )
            return "Linux\n"
        if cmd == "cd":
            return self._cd(args[0] if args else "/root")
        if cmd == "ls":
            return self._ls(args)
        if cmd == "cat":
            return self._cat(args)
        if cmd == "echo":
            text = " ".join(args)
            text = text.replace("$USER", self.user).replace("$HOSTNAME", self.hostname)
            return text + "\n"
        if cmd == "ps":
            return (
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root           1  0.0  0.1 167424 11820 ?        Ss   Nov20   0:03 /sbin/init\n"
                "root         742  0.0  0.2 235612 20112 ?        Ss   Nov20   0:00 /usr/sbin/sshd -D\n"
                "www-data     912  0.0  0.3 456220 30212 ?        S    Nov20   0:01 nginx: worker process\n"
                "root        1024  0.0  0.1  12112  4320 ?        Ss   Nov20   0:00 cron\n"
            )
        if cmd in {"ip", "ifconfig"}:
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
                "    inet 10.20.30.41/24 brd 10.20.30.255 scope global eth0\n"
            )
        if cmd in {"ss", "netstat"}:
            return (
                "State   Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
                "LISTEN  0      128    0.0.0.0:22          0.0.0.0:*     users:((\"sshd\",pid=742,fd=3))\n"
                "LISTEN  0      511    0.0.0.0:80          0.0.0.0:*     users:((\"nginx\",pid=912,fd=6))\n"
                "LISTEN  0      128    127.0.0.1:3306      0.0.0.0:*     users:((\"mysqld\",pid=811,fd=22))\n"
            )
        if cmd == "df":
            return (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        79G   31G   44G  42% /\n"
                "tmpfs           1.6G     0  1.6G   0% /dev/shm\n"
            )
        if cmd == "free":
            return (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:           3.8Gi       1.1Gi       512Mi        12Mi       2.2Gi       2.4Gi\n"
                "Swap:          2.0Gi          0B       2.0Gi\n"
            )
        if cmd == "uptime":
            return " 14:32:07 up 41 days,  3:18,  1 user,  load average: 0.08, 0.03, 0.01\n"
        if cmd == "date":
            return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y") + "\n"
        if cmd == "history":
            return "\n".join(f"{i + 1:5d}  {item}" for i, item in enumerate(self.history)) + "\n"
        if cmd == "env":
            return (
                f"USER={self.user}\nHOME={self.cwd}\nSHELL=/bin/bash\n"
                f"HOSTNAME={self.hostname}\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "LANG=en_US.UTF-8\n"
            )
        if cmd == "sudo":
            if "-l" in args:
                return "Matching Defaults entries for ubuntu on ubuntu:\n    env_reset, mail_badpass\n"
            return "sudo: a terminal is required to read the password; either use the -S option\n"
        if cmd == "systemctl":
            unit = args[-1] if args else "nginx"
            return f"● {unit}.service - {unit}\n     Loaded: loaded (/lib/systemd/system/{unit}.service; enabled)\n     Active: active (running)\n"
        if cmd == "docker":
            return "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n"
        if cmd in {"wget", "curl"}:
            return "curl: (7) Failed to connect to 10.20.30.10 port 8080 after 3001 ms: Connection refused\n" if cmd == "curl" else "Connecting to 10.20.30.10:8080... failed: Connection refused.\n"
        if cmd in {"apt", "apt-get", "dpkg"}:
            return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
        if cmd == "touch":
            for name in args:
                self.files[self._resolve(name)] = ""
            return ""
        if cmd == "mkdir":
            for name in [a for a in args if not a.startswith("-")]:
                self.dirs.add(self._resolve(name))
            return ""
        if cmd == "rm":
            for name in [a for a in args if not a.startswith("-")]:
                self.files.pop(self._resolve(name), None)
            return ""
        if cmd == "find":
            return "\n".join(sorted(self.files)) + "\n"
        if cmd == "grep":
            if len(args) >= 2:
                needle, path = args[0], self._resolve(args[1])
                if path in self.files:
                    hits = [f"{path}:{row}" for row in self.files[path].splitlines() if needle in row]
                    return "\n".join(hits) + ("\n" if hits else "")
            return ""
        return f"bash: {cmd}: command not found\n"

    def _resolve(self, path: str) -> str:
        if path in {"", "."}:
            return self.cwd
        if path == "..":
            return posixpath.dirname(self.cwd) or "/"
        if path.startswith("/"):
            return posixpath.normpath(path)
        return posixpath.normpath(posixpath.join(self.cwd, path))

    def _cd(self, path: str) -> str:
        target = self._resolve(path)
        if target in self.dirs:
            self.cwd = target
            return ""
        return f"bash: cd: {path}: No such file or directory\n"

    def _ls(self, args: list[str]) -> str:
        long = any(arg.startswith("-") and "l" in arg for arg in args)
        target = self._resolve(next((a for a in args if not a.startswith("-")), "."))
        if target in self.files:
            return target.split("/")[-1] + "\n"
        if target not in self.dirs:
            return f"ls: cannot access '{target}': No such file or directory\n"
        children = sorted(
            {p[len(target.rstrip('/')) + 1:].split("/")[0]
             for p in list(self.dirs) + list(self.files)
             if p.startswith(target.rstrip("/") + "/") and p != target}
        )
        if long:
            rows = ["total 32", "drwxr-xr-x  2 root root 4096 Nov 20 09:12 .", "drwxr-xr-x 18 root root 4096 Nov 19 18:04 .."]
            rows += [f"-rw-r--r--  1 root root  128 Nov 20 09:12 {name}" for name in children]
            return "\n".join(rows) + "\n"
        return "  ".join(children) + ("\n" if children else "")

    def _cat(self, args: list[str]) -> str:
        if not args:
            return ""
        path = self._resolve(args[0])
        if path in self.files:
            return self.files[path]
        return f"cat: {args[0]}: No such file or directory\n"
