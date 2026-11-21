from honeypot.shell import FakeShell


def test_fake_shell_looks_like_a_real_ubuntu_host():
    shell = FakeShell()
    assert "root@ubuntu:/root#" in shell.prompt()
    assert "Ubuntu 22.04.3 LTS" in shell.execute("cat /etc/os-release")
    assert "10.20.30.41" in shell.execute("ip addr")
    assert "sshd" in shell.execute("ps aux")
    assert "command not found" not in shell.execute("ls -la")


def test_fake_shell_tracks_cwd_and_never_executes():
    shell = FakeShell()
    assert shell.execute("cd /srv/backup") == ""
    assert shell.execute("pwd").strip() == "/srv/backup"
    assert "finance_q4.csv" in shell.execute("ls")
    uploaded = shell.execute("touch note.txt")
    assert uploaded == ""
    assert "note.txt" in shell.execute("ls")
    assert "Connection refused" in shell.execute("curl http://10.20.30.10")
