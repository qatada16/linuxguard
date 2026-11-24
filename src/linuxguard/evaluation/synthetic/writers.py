import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime

UNSET = 4294967295
SAFE_CHARACTERS = frozenset(chr(code) for code in range(33, 127)) - {'"', "'"}

SYSCALL_NUMBERS = {
    "execve": 59,
    "openat": 257,
    "connect": 42,
    "rename": 82,
    "renameat2": 316,
    "unlinkat": 263,
    "fchmodat": 268,
    "finit_module": 313,
    "truncate": 76,
}
OPEN_READ = 0x0
OPEN_WRITE_TRUNCATE = 0x241
OPEN_APPEND = 0x441
LOADER = "/lib64/ld-linux-x86-64.so.2"


def encode_audit_string(value: str) -> str:
    if value and all(character in SAFE_CHARACTERS for character in value):
        return f'"{value}"'
    return value.encode("utf-8").hex().upper()


def encode_socket_address(ip: str, port: int) -> str:
    if ":" in ip:
        packed = ipaddress.IPv6Address(ip).packed
        return ("0A00" + f"{port:04X}" + "00000000" + packed.hex().upper() + "00000000").upper()
    octets = "".join(f"{int(part):02X}" for part in ip.split("."))
    return "0200" + f"{port:04X}" + octets + "0000000000000000"


def iso_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat(timespec="microseconds")


@dataclass(slots=True)
class Process:
    user: str
    uid: int
    gid: int
    auid: int
    session: int
    tty: str
    pid: int
    executable: str
    euid: int | None = None

    @property
    def comm(self) -> str:
        return self.executable.rsplit("/", 1)[-1][:15]


@dataclass(slots=True)
class LogSink:
    audit: list[tuple[float, int, int, str]] = field(default_factory=list)
    auth: list[tuple[float, int, str]] = field(default_factory=list)

    def sorted_audit_lines(self) -> list[str]:
        return [line for *_, line in sorted(self.audit, key=lambda item: (item[0], item[1], item[2]))]

    def sorted_auth_lines(self) -> list[str]:
        return [line for *_, line in sorted(self.auth, key=lambda item: (item[0], item[1]))]


class AuditLogWriter:
    def __init__(self, sink: LogSink, start_serial: int = 1000) -> None:
        self._sink = sink
        self._serial = start_serial

    def _emit(self, timestamp: float, bodies: list[tuple[str, str]]) -> None:
        self._serial += 1
        stamp = f"{timestamp:.3f}"
        for index, (record_type, body) in enumerate(bodies):
            separator = " " if body else ""
            line = f"type={record_type} msg=audit({stamp}:{self._serial}):{separator}{body}"
            self._sink.audit.append((round(timestamp, 3), self._serial, index, line))
        self._sink.audit.append(
            (round(timestamp, 3), self._serial, len(bodies), f"type=EOE msg=audit({stamp}:{self._serial}): ")
        )

    def _syscall(
        self,
        process: Process,
        parent_pid: int,
        syscall: str,
        key: str,
        items: int,
        success: bool = True,
        exit_code: int = 0,
        arguments: tuple[str, str, str] = ("3", "7ffd5a1c2e40", "0"),
        executable: str | None = None,
    ) -> str:
        euid = process.uid if process.euid is None else process.euid
        exe = executable or process.executable
        comm = exe.rsplit("/", 1)[-1][:15]
        return (
            f"arch=c000003e syscall={SYSCALL_NUMBERS[syscall]} success={'yes' if success else 'no'} "
            f"exit={exit_code} a0={arguments[0]} a1={arguments[1]} a2={arguments[2]} a3=0 items={items} "
            f"ppid={parent_pid} pid={process.pid} auid={process.auid} uid={process.uid} gid={process.gid} "
            f"euid={euid} suid={euid} fsuid={euid} egid={process.gid} sgid={process.gid} fsgid={process.gid} "
            f"tty={process.tty} ses={process.session} comm={encode_audit_string(comm)} "
            f"exe={encode_audit_string(exe)} subj=unconfined key={encode_audit_string(key)}"
        )

    @staticmethod
    def _proctitle(arguments: list[str]) -> tuple[str, str]:
        return "PROCTITLE", f"proctitle={chr(0).join(arguments).encode('utf-8').hex().upper()}"

    @staticmethod
    def _path(item: int, name: str, nametype: str, mode: str = "0100644") -> tuple[str, str]:
        return (
            "PATH",
            f"item={item} name={encode_audit_string(name)} inode={100000 + item} dev=08:01 mode={mode} "
            f"ouid=0 ogid=0 rdev=00:00 nametype={nametype} cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0",
        )

    def execution(
        self,
        timestamp: float,
        process: Process,
        parent_pid: int,
        arguments: list[str],
        cwd: str,
        success: bool = True,
    ) -> None:
        execve = " ".join(f"a{index}={encode_audit_string(value)}" for index, value in enumerate(arguments))
        self._emit(
            timestamp,
            [
                (
                    "SYSCALL",
                    self._syscall(process, parent_pid, "execve", "lg_exec", 2, success, 0 if success else -2),
                ),
                ("EXECVE", f"argc={len(arguments)} {execve}"),
                ("CWD", f"cwd={encode_audit_string(cwd)}"),
                self._path(0, process.executable, "NORMAL", "0100755"),
                self._path(1, LOADER, "NORMAL", "0100755"),
                self._proctitle(arguments),
            ],
        )

    def file_open(
        self,
        timestamp: float,
        process: Process,
        parent_pid: int,
        path: str,
        flags: int,
        key: str,
        cwd: str,
        command: list[str],
        created: bool = False,
    ) -> None:
        self._emit(
            timestamp,
            [
                (
                    "SYSCALL",
                    self._syscall(
                        process,
                        parent_pid,
                        "openat",
                        key,
                        1,
                        arguments=("ffffff9c", "7ffd5a1c3f10", f"{flags:x}"),
                    ),
                ),
                ("CWD", f"cwd={encode_audit_string(cwd)}"),
                self._path(0, path, "CREATE" if created else "NORMAL"),
                self._proctitle(command),
            ],
        )

    def rename(
        self,
        timestamp: float,
        process: Process,
        parent_pid: int,
        source: str,
        destination: str,
        key: str,
        command: list[str],
    ) -> None:
        source_directory = source.rsplit("/", 1)[0] or "/"
        destination_directory = destination.rsplit("/", 1)[0] or "/"
        self._emit(
            timestamp,
            [
                ("SYSCALL", self._syscall(process, parent_pid, "rename", key, 4)),
                ("CWD", f"cwd={encode_audit_string(source_directory)}"),
                self._path(0, source_directory, "PARENT", "040755"),
                self._path(1, destination_directory, "PARENT", "040755"),
                self._path(2, source, "DELETE"),
                self._path(3, destination, "CREATE"),
                self._proctitle(command),
            ],
        )

    def unlink(
        self, timestamp: float, process: Process, parent_pid: int, path: str, key: str, command: list[str]
    ) -> None:
        directory = path.rsplit("/", 1)[0] or "/"
        self._emit(
            timestamp,
            [
                ("SYSCALL", self._syscall(process, parent_pid, "unlinkat", key, 2)),
                ("CWD", f"cwd={encode_audit_string(directory)}"),
                self._path(0, directory, "PARENT", "040755"),
                self._path(1, path, "DELETE"),
                self._proctitle(command),
            ],
        )

    def chmod(
        self, timestamp: float, process: Process, parent_pid: int, path: str, mode: int, command: list[str]
    ) -> None:
        self._emit(
            timestamp,
            [
                (
                    "SYSCALL",
                    self._syscall(
                        process,
                        parent_pid,
                        "fchmodat",
                        "lg_perm",
                        1,
                        arguments=("ffffff9c", "55d1c2a0", f"{mode:x}"),
                    ),
                ),
                ("CWD", f"cwd={encode_audit_string(path.rsplit('/', 1)[0] or '/')}"),
                self._path(0, path, "NORMAL", "0100755"),
                self._proctitle(command),
            ],
        )

    def connect(
        self,
        timestamp: float,
        process: Process,
        parent_pid: int,
        ip: str,
        port: int,
        command: list[str],
        blocking: bool = True,
    ) -> None:
        length = "1c" if ":" in ip else "10"
        self._emit(
            timestamp,
            [
                (
                    "SYSCALL",
                    self._syscall(
                        process,
                        parent_pid,
                        "connect",
                        "lg_network",
                        0,
                        success=blocking,
                        exit_code=0 if blocking else -115,
                        arguments=("3", "7ffd5a1c4a20", length),
                    ),
                ),
                ("SOCKADDR", f"saddr={encode_socket_address(ip, port)}"),
                self._proctitle(command),
            ],
        )

    def module_load(self, timestamp: float, process: Process, parent_pid: int, module: str, command: list[str]) -> None:
        self._emit(
            timestamp,
            [
                ("SYSCALL", self._syscall(process, parent_pid, "finit_module", "lg_kernel_module", 0)),
                ("KERN_MODULE", f"name={encode_audit_string(module)}"),
                self._proctitle(command),
            ],
        )

    def _user_record(self, timestamp: float, record_type: str, header: str, message: str) -> None:
        self._serial += 1
        line = f"type={record_type} msg=audit({timestamp:.3f}:{self._serial}): {header} msg='{message}'"
        self._sink.audit.append((round(timestamp, 3), self._serial, 0, line))

    def user_auth(
        self,
        timestamp: float,
        pid: int,
        account: str,
        address: str | None,
        success: bool,
        terminal: str = "ssh",
        exe: str = "/usr/sbin/sshd",
        auid: int = UNSET,
        session: int = UNSET,
        uid: int = 0,
    ) -> None:
        grantors = "pam_permit,pam_cap" if success else "?"
        host = address or "?"
        self._user_record(
            timestamp,
            "USER_AUTH",
            f"pid={pid} uid={uid} auid={auid} ses={session} subj=unconfined",
            f'op=PAM:authentication grantors={grantors} acct="{account}" exe="{exe}" hostname={host} '
            f"addr={host} terminal={terminal} res={'success' if success else 'failed'}",
        )

    def user_login(
        self,
        timestamp: float,
        pid: int,
        account: str,
        uid: int | None,
        address: str,
        success: bool,
        auid: int = UNSET,
        session: int = UNSET,
    ) -> None:
        identity = f"id={uid}" if success and uid is not None else f'acct="{account}"'
        terminal = "/dev/pts/0" if success else "sshd"
        self._user_record(
            timestamp,
            "USER_LOGIN",
            f"pid={pid} uid=0 auid={auid} ses={session} subj=unconfined",
            f'op=login {identity} exe="/usr/sbin/sshd" hostname=? addr={address} terminal={terminal} '
            f"res={'success' if success else 'failed'}",
        )

    def user_command(self, timestamp: float, process: Process, cwd: str, command: str, success: bool = True) -> None:
        self._user_record(
            timestamp,
            "USER_CMD",
            f"pid={process.pid} uid={process.uid} auid={process.auid} ses={process.session} subj=unconfined",
            f'cwd="{cwd}" cmd={command.encode("utf-8").hex().upper()} exe="/usr/bin/sudo" '
            f"terminal={process.tty} res={'success' if success else 'failed'}",
        )

    def account_change(
        self,
        timestamp: float,
        process: Process,
        record_type: str,
        operation: str,
        account: str,
        group: str | None = None,
        exe: str = "/usr/sbin/useradd",
    ) -> None:
        group_field = f'grp="{group}" ' if group else ""
        self._user_record(
            timestamp,
            record_type,
            f"pid={process.pid} uid=0 auid={process.auid} ses={process.session} subj=unconfined",
            f'op={operation} {group_field}acct="{account}" exe="{exe}" hostname=? addr=? '
            f"terminal={process.tty} res=success",
        )

    def configuration_change(self, timestamp: float, auid: int, session: int, operation: str, key: str) -> None:
        self._serial += 1
        line = (
            f"type=CONFIG_CHANGE msg=audit({timestamp:.3f}:{self._serial}): auid={auid} ses={session} "
            f'subj=unconfined op={operation} key="{key}" list=4 res=1'
        )
        self._sink.audit.append((round(timestamp, 3), self._serial, 0, line))


class AuthLogWriter:
    def __init__(self, sink: LogSink, host: str) -> None:
        self._sink = sink
        self._host = host
        self._sequence = 0

    def _emit(self, timestamp: float, program: str, pid: int, message: str) -> None:
        self._sequence += 1
        line = f"{iso_timestamp(timestamp)} {self._host} {program}[{pid}]: {message}"
        self._sink.auth.append((timestamp, self._sequence, line))

    def ssh_failure(self, timestamp: float, pid: int, user: str, ip: str, port: int, invalid: bool = False) -> None:
        prefix = "invalid user " if invalid else ""
        self._emit(timestamp, "sshd", pid, f"Failed password for {prefix}{user} from {ip} port {port} ssh2")

    def ssh_success(self, timestamp: float, pid: int, user: str, ip: str, port: int, method: str = "publickey") -> None:
        suffix = ": ED25519 SHA256:kq3Hx0lJ0bq8n5d2mW1u5gq1Yq3Zr7dN0Rk9xY2pV4c" if method == "publickey" else ""
        self._emit(timestamp, "sshd", pid, f"Accepted {method} for {user} from {ip} port {port} ssh2{suffix}")

    def sudo_command(self, timestamp: float, pid: int, user: str, tty: str, cwd: str, command: str) -> None:
        self._emit(timestamp, "sudo", pid, f"   {user} : TTY={tty} ; PWD={cwd} ; USER=root ; COMMAND={command}")

    def sudo_denied(self, timestamp: float, pid: int, user: str, tty: str, cwd: str, command: str) -> None:
        self._emit(
            timestamp,
            "sudo",
            pid,
            f"   {user} : user NOT in sudoers ; TTY={tty} ; PWD={cwd} ; USER=root ; COMMAND={command}",
        )

    def pam_failure(self, timestamp: float, pid: int, service: str, user: str, uid: int, tty: str) -> None:
        self._emit(
            timestamp,
            service,
            pid,
            f"pam_unix({service}:auth): authentication failure; logname={user} uid={uid} euid=0 tty={tty} "
            f"ruser={user} rhost=  user={user}",
        )

    def new_user(self, timestamp: float, pid: int, name: str, uid: int) -> None:
        self._emit(
            timestamp,
            "useradd",
            pid,
            f"new user: name={name}, UID={uid}, GID={uid}, home=/home/{name}, shell=/bin/bash, from=/dev/pts/1",
        )

    def group_membership(self, timestamp: float, pid: int, name: str, group: str) -> None:
        self._emit(timestamp, "usermod", pid, f"add '{name}' to group '{group}'")
