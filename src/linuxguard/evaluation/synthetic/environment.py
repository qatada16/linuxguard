import random
from dataclasses import dataclass, field

from linuxguard.evaluation.labels import Case
from linuxguard.evaluation.synthetic.writers import UNSET, AuditLogWriter, AuthLogWriter, LogSink, Process

DEFAULT_HOST = "lab-ubuntu"

COMMAND_PATHS = {
    "adduser": "/usr/sbin/adduser",
    "apt": "/usr/bin/apt",
    "auditctl": "/usr/sbin/auditctl",
    "awk": "/usr/bin/gawk",
    "base64": "/usr/bin/base64",
    "bash": "/usr/bin/bash",
    "cat": "/usr/bin/cat",
    "chmod": "/usr/bin/chmod",
    "cp": "/usr/bin/cp",
    "crontab": "/usr/bin/crontab",
    "curl": "/usr/bin/curl",
    "df": "/usr/bin/df",
    "dpkg": "/usr/bin/dpkg",
    "find": "/usr/bin/find",
    "free": "/usr/bin/free",
    "gcc": "/usr/bin/x86_64-linux-gnu-gcc-13",
    "git": "/usr/bin/git",
    "grep": "/usr/bin/grep",
    "gzip": "/usr/bin/gzip",
    "head": "/usr/bin/head",
    "hostname": "/usr/bin/hostname",
    "id": "/usr/bin/id",
    "insmod": "/usr/bin/kmod",
    "ip": "/usr/bin/ip",
    "journalctl": "/usr/bin/journalctl",
    "last": "/usr/bin/last",
    "less": "/usr/bin/less",
    "logrotate": "/usr/sbin/logrotate",
    "ls": "/usr/bin/ls",
    "lscpu": "/usr/bin/lscpu",
    "make": "/usr/bin/make",
    "nproc": "/usr/bin/nproc",
    "npm": "/usr/bin/node",
    "passwd": "/usr/bin/passwd",
    "ps": "/usr/bin/ps",
    "python3": "/usr/bin/python3.12",
    "rm": "/usr/bin/rm",
    "rsync": "/usr/bin/rsync",
    "run-parts": "/usr/bin/run-parts",
    "sh": "/usr/bin/dash",
    "sort": "/usr/bin/sort",
    "split": "/usr/bin/split",
    "ss": "/usr/bin/ss",
    "ssh": "/usr/bin/ssh",
    "sudo": "/usr/bin/sudo",
    "systemctl": "/usr/bin/systemctl",
    "tail": "/usr/bin/tail",
    "tar": "/usr/bin/tar",
    "tee": "/usr/bin/tee",
    "top": "/usr/bin/top",
    "uname": "/usr/bin/uname",
    "uniq": "/usr/bin/uniq",
    "uptime": "/usr/bin/uptime",
    "useradd": "/usr/sbin/useradd",
    "usermod": "/usr/sbin/usermod",
    "vim": "/usr/bin/vim.basic",
    "w": "/usr/bin/w",
    "wc": "/usr/bin/wc",
    "wget": "/usr/bin/wget",
    "who": "/usr/bin/who",
    "whoami": "/usr/bin/whoami",
}


@dataclass(frozen=True, slots=True)
class Account:
    name: str
    uid: int
    role: str
    workstation: str
    home: str = ""

    @property
    def home_directory(self) -> str:
        return self.home or f"/home/{self.name}"


ACCOUNTS: tuple[Account, ...] = (
    Account("alice", 1001, "developer", "10.0.0.11"),
    Account("bob", 1002, "developer", "10.0.0.12"),
    Account("carol", 1003, "analyst", "10.0.0.13"),
    Account("dave", 1004, "administrator", "10.0.0.14"),
)
ROOT = Account("root", 0, "system", "127.0.0.1", "/root")
WEB_SERVICE = Account("www-data", 33, "service", "127.0.0.1", "/var/www")
SYSTEM_ACCOUNTS = (ROOT, Account("daemon", 1, "service", "127.0.0.1", "/usr/sbin"), WEB_SERVICE)
ATTACKER_NETWORKS = ("203.0.113", "198.51.100")


@dataclass(slots=True)
class ShellSession:
    environment: "SimulationEnvironment"
    account: Account
    session: int
    tty: str
    shell: Process
    cwd: str
    source_ip: str | None = None

    def process(self, executable: str, euid: int | None = None) -> Process:
        return Process(
            user=self.account.name,
            uid=self.account.uid,
            gid=self.account.uid,
            auid=self.account.uid,
            session=self.session,
            tty=self.tty,
            pid=self.environment.next_pid(),
            executable=executable,
            euid=euid,
        )

    def run(
        self, timestamp: float, arguments: list[str], parent: Process | None = None, as_root: bool = False
    ) -> Process:
        executable = COMMAND_PATHS.get(arguments[0], arguments[0])
        process = self.process(executable, euid=0 if as_root else None)
        parent_pid = (parent or self.shell).pid
        self.environment.audit.execution(timestamp, process, parent_pid, arguments, self.cwd)
        return process

    def sudo(self, timestamp: float, arguments: list[str]) -> Process:
        command = " ".join(arguments)
        sudo_process = self.process(COMMAND_PATHS["sudo"], euid=0)
        self.environment.audit.execution(timestamp, sudo_process, self.shell.pid, ["sudo", *arguments], self.cwd)
        self.environment.audit.user_command(timestamp + 0.01, sudo_process, self.cwd, command)
        full_command = " ".join([COMMAND_PATHS.get(arguments[0], arguments[0]), *arguments[1:]])
        self.environment.auth.sudo_command(
            timestamp + 0.02, sudo_process.pid, self.account.name, self.tty_device, self.cwd, full_command
        )
        return self.run(timestamp + 0.05, arguments, parent=sudo_process, as_root=True)

    @property
    def tty_device(self) -> str:
        return f"/dev/{self.tty.replace('pts', 'pts/')}" if self.tty.startswith("pts") else self.tty


@dataclass
class SimulationEnvironment:
    seed: int
    host: str = DEFAULT_HOST
    rng: random.Random = field(init=False)
    sink: LogSink = field(default_factory=LogSink)
    cases: list[Case] = field(default_factory=list)
    services: dict[str, Process] = field(default_factory=dict)
    _pid: int = 1500
    _session: int = 10
    _case_counter: int = 0

    def __post_init__(self) -> None:
        self.rng = random.Random(self.seed)
        self.audit = AuditLogWriter(self.sink, start_serial=1000 + self.seed * 10)
        self.auth = AuthLogWriter(self.sink, self.host)

    def next_pid(self) -> int:
        self._pid += self.rng.randint(1, 7)
        if self._pid > 4_000_000:
            self._pid = 1500
        return self._pid

    def next_session(self) -> int:
        self._session += 1
        return self._session

    def attacker_ip(self) -> str:
        return f"{self.rng.choice(ATTACKER_NETWORKS)}.{self.rng.randint(2, 250)}"

    def ephemeral_port(self) -> int:
        return self.rng.randint(32768, 60999)

    def add_case(
        self,
        scenario: str,
        malicious: bool,
        start: float,
        end: float,
        selectors: dict[str, list[str]],
        covered_by_rules: bool | None,
        description: str,
    ) -> Case:
        self._case_counter += 1
        case = Case(
            case_id=f"{scenario}-{self._case_counter:04d}",
            scenario=scenario,
            malicious=malicious,
            start=start,
            end=end,
            selectors={key: sorted(set(values)) for key, values in selectors.items()},
            covered_by_rules=covered_by_rules,
            description=description,
        )
        self.cases.append(case)
        return case

    def service_process(self, account: Account, executable: str) -> Process:
        return Process(
            user=account.name,
            uid=account.uid,
            gid=account.uid,
            auid=UNSET,
            session=UNSET,
            tty="(none)",
            pid=self.next_pid(),
            executable=executable,
        )

    def ssh_login(self, timestamp: float, account: Account, source_ip: str, method: str = "publickey") -> ShellSession:
        sshd_pid = self.next_pid()
        port = self.ephemeral_port()
        self.audit.user_auth(timestamp, sshd_pid, account.name, source_ip, True)
        self.auth.ssh_success(timestamp + 0.003, sshd_pid, account.name, source_ip, port, method)
        session = self.next_session()
        self.audit.user_login(
            timestamp + 0.05, sshd_pid, account.name, account.uid, source_ip, True, account.uid, session
        )
        tty = f"pts{self.rng.randint(0, 6)}"
        shell = Process(
            account.name,
            account.uid,
            account.uid,
            account.uid,
            session,
            tty,
            self.next_pid(),
            "/usr/bin/bash",
        )
        self.audit.execution(timestamp + 0.1, shell, sshd_pid, ["-bash"], account.home_directory)
        return ShellSession(self, account, session, tty, shell, account.home_directory, source_ip)

    def ssh_failure(self, timestamp: float, user: str, source_ip: str, invalid: bool = False) -> None:
        sshd_pid = self.next_pid()
        self.audit.user_auth(timestamp, sshd_pid, "(invalid user)" if invalid else user, source_ip, False)
        self.audit.user_login(timestamp + 0.4, sshd_pid, user, None, source_ip, False)
        self.auth.ssh_failure(timestamp + 0.002, sshd_pid, user, source_ip, self.ephemeral_port(), invalid)

    def system_session(self, account: Account = ROOT, tty: str = "(none)") -> ShellSession:
        session = self.next_session()
        shell = Process(
            account.name,
            account.uid,
            account.uid,
            account.uid,
            session,
            tty,
            self.next_pid(),
            "/usr/bin/dash",
        )
        return ShellSession(self, account, session, tty, shell, account.home_directory)

    def passwd_lines(self) -> list[str]:
        accounts = (*SYSTEM_ACCOUNTS, *ACCOUNTS)
        return [
            f"{account.name}:x:{account.uid}:{account.uid}::{account.home_directory}:/bin/bash" for account in accounts
        ]
