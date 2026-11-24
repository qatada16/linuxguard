from collections.abc import Callable
from dataclasses import dataclass

from linuxguard.evaluation.labels import Case
from linuxguard.evaluation.synthetic.environment import (
    COMMAND_PATHS,
    ROOT,
    WEB_SERVICE,
    Account,
    ShellSession,
    SimulationEnvironment,
)
from linuxguard.evaluation.synthetic.writers import OPEN_READ

HOUR = 3600.0
GITHUB = "140.82.112.3"
PACKAGE_MIRROR = "91.189.91.81"
NPM_REGISTRY = "104.16.24.35"
DATA_PORTAL = "93.184.216.34"
MONITORING_SERVER = "10.0.0.5"
REMOTE_WORK_PROBABILITY = 0.2

CommandAction = Callable[[ShellSession, float], float]


@dataclass(frozen=True, slots=True)
class WeightedCommand:
    weight: float
    action: CommandAction


def _simple(*arguments: str) -> CommandAction:
    def action(shell: ShellSession, timestamp: float) -> float:
        shell.run(timestamp, list(arguments))
        return timestamp + 0.2

    return action


def _git_network(subcommand: str) -> CommandAction:
    def action(shell: ShellSession, timestamp: float) -> float:
        process = shell.run(timestamp, ["git", subcommand])
        shell.environment.audit.connect(timestamp + 0.3, process, shell.shell.pid, GITHUB, 443, ["git", subcommand])
        rng = shell.environment.rng
        for index in range(rng.randint(2, 8)):
            temporary = f"{shell.cwd}/.git/objects/pack/tmp_pack_{rng.randint(1000, 9999)}{index}"
            final = f"{shell.cwd}/.git/objects/pack/pack-{rng.getrandbits(40):010x}.pack"
            shell.environment.audit.rename(
                timestamp + 0.6 + index * 0.05,
                process,
                shell.shell.pid,
                temporary,
                final,
                "lg_home_change",
                ["git", subcommand],
            )
        return timestamp + 1.5

    return action


def _editor(file_name: str) -> CommandAction:
    def action(shell: ShellSession, timestamp: float) -> float:
        process = shell.run(timestamp, ["vim", file_name])
        swap = f"{shell.cwd}/.{file_name.rsplit('/', 1)[-1]}.swp"
        duration = shell.environment.rng.uniform(20, 240)
        shell.environment.audit.unlink(
            timestamp + duration, process, shell.shell.pid, swap, "lg_home_change", ["vim", file_name]
        )
        return timestamp + duration

    return action


def _https_fetch(command: list[str], destination: str, connections: int = 1) -> CommandAction:
    def action(shell: ShellSession, timestamp: float) -> float:
        process = shell.run(timestamp, command)
        for index in range(connections):
            shell.environment.audit.connect(
                timestamp + 0.2 + index * 0.3, process, shell.shell.pid, destination, 443, command
            )
        return timestamp + 0.5 + connections * 0.3

    return action


def _sudo(*arguments: str, connections: tuple[str, int, int] | None = None) -> CommandAction:
    def action(shell: ShellSession, timestamp: float) -> float:
        process = shell.sudo(timestamp, list(arguments))
        if connections is not None:
            destination, port, count = connections
            for index in range(count):
                shell.environment.audit.connect(
                    timestamp + 0.5 + index * 0.4,
                    process,
                    shell.shell.pid,
                    destination,
                    port,
                    list(arguments),
                )
        return timestamp + 1.0

    return action


def _package_download(shell: ShellSession, timestamp: float) -> float:
    rng = shell.environment.rng
    command = ["python3", "-m", "pip", "install", "-q", "-r", "requirements.txt"]
    process = shell.run(timestamp, command)
    for index in range(rng.randint(1, 4)):
        cdn = f"151.101.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        shell.environment.audit.connect(timestamp + 0.3 + index * 0.4, process, shell.shell.pid, cdn, 443, command)
    return timestamp + 2.0


def _read_hosts(shell: ShellSession, timestamp: float) -> float:
    shell.run(timestamp, ["cat", "/etc/hosts"])
    return timestamp + 0.2


DEVELOPER_COMMANDS = (
    WeightedCommand(8, _simple("ls", "-la")),
    WeightedCommand(6, _simple("git", "status")),
    WeightedCommand(2, _git_network("pull")),
    WeightedCommand(1.5, _git_network("push")),
    WeightedCommand(5, _editor("src/app.py")),
    WeightedCommand(3, _simple("python3", "manage.py", "test")),
    WeightedCommand(3, _simple("python3", "-m", "pytest", "-q")),
    WeightedCommand(2, _simple("make")),
    WeightedCommand(4, _simple("grep", "-rn", "TODO", "src")),
    WeightedCommand(4, _simple("cat", "README.md")),
    WeightedCommand(2, _simple("less", "logs/app.log")),
    WeightedCommand(1, _https_fetch(["npm", "install"], NPM_REGISTRY, 4)),
    WeightedCommand(1, _https_fetch(["curl", "-s", "https://api.github.com/repos"], GITHUB)),
    WeightedCommand(1, _read_hosts),
    WeightedCommand(1, _package_download),
)
ANALYST_COMMANDS = (
    WeightedCommand(8, _simple("ls", "-lh", "data")),
    WeightedCommand(5, _simple("head", "-n", "20", "data/sales.csv")),
    WeightedCommand(4, _simple("tail", "-n", "50", "data/sales.csv")),
    WeightedCommand(4, _simple("grep", "-c", "error", "data/report.txt")),
    WeightedCommand(3, _simple("awk", "-F,", "{print $3}", "data/sales.csv")),
    WeightedCommand(3, _simple("sort", "data/ids.txt")),
    WeightedCommand(2, _simple("wc", "-l", "data/sales.csv")),
    WeightedCommand(5, _simple("python3", "analysis.py")),
    WeightedCommand(3, _editor("notes.md")),
    WeightedCommand(2, _https_fetch(["curl", "-sO", "https://data.example.org/export.csv"], DATA_PORTAL)),
    WeightedCommand(2, _simple("less", "data/report.txt")),
)
ADMINISTRATOR_COMMANDS = (
    WeightedCommand(4, _sudo("systemctl", "status", "nginx")),
    WeightedCommand(3, _sudo("journalctl", "-u", "nginx", "--since", "today")),
    WeightedCommand(4, _simple("df", "-h")),
    WeightedCommand(3, _simple("free", "-m")),
    WeightedCommand(3, _simple("uptime")),
    WeightedCommand(3, _simple("ps", "aux")),
    WeightedCommand(2, _simple("top", "-bn1")),
    WeightedCommand(2, _simple("ss", "-tlnp")),
    WeightedCommand(1, _simple("ip", "a")),
    WeightedCommand(2, _simple("tail", "-n", "100", "/var/log/syslog")),
    WeightedCommand(1, _sudo("apt", "update", connections=(PACKAGE_MIRROR, 80, 3))),
    WeightedCommand(2, _sudo("tail", "-n", "50", "/var/log/auth.log")),
    WeightedCommand(1, _simple("who")),
    WeightedCommand(2, _read_hosts),
    WeightedCommand(2, _sudo("systemctl", "restart", "nginx")),
    WeightedCommand(3, _simple("ls", "-la", "/etc/nginx/sites-enabled")),
)
ROLE_COMMANDS = {
    "developer": DEVELOPER_COMMANDS,
    "analyst": ANALYST_COMMANDS,
    "administrator": ADMINISTRATOR_COMMANDS,
}
ROLE_DIRECTORIES = {"developer": "projects/webapp", "analyst": "analysis", "administrator": ""}


def start_services(environment: SimulationEnvironment, timestamp: float) -> None:
    for name, account, executable in (
        ("cron", ROOT, "/usr/sbin/cron"),
        ("nginx", ROOT, "/usr/sbin/nginx"),
        ("php-fpm", WEB_SERVICE, "/usr/sbin/php-fpm8.3"),
    ):
        process = environment.service_process(account, executable)
        environment.audit.execution(timestamp, process, 1, [executable.rsplit("/", 1)[-1]], "/")
        environment.services[name] = process
        timestamp += 0.5


def work_session(environment: SimulationEnvironment, account: Account, start: float, duration: float) -> Case:
    rng = environment.rng
    source_ip = account.workstation if rng.random() > REMOTE_WORK_PROBABILITY else f"192.0.2.{rng.randint(1, 254)}"
    shell = environment.ssh_login(start, account, source_ip)
    directory = ROLE_DIRECTORIES[account.role]
    if directory:
        shell.cwd = f"{account.home_directory}/{directory}"
    commands = ROLE_COMMANDS[account.role]
    weights = [command.weight for command in commands]
    timestamp = start + rng.uniform(2, 10)
    end = start + duration
    while timestamp < end:
        command = rng.choices(commands, weights)[0]
        timestamp = command.action(shell, timestamp)
        pause = rng.expovariate(1 / 35) if rng.random() > 0.15 else rng.uniform(1, 4)
        timestamp += pause
    return environment.add_case(
        "work_session",
        False,
        start,
        max(timestamp, end),
        {"session_id": [str(shell.session)], "src_ip": [source_ip]},
        None,
        f"Routine {account.role} activity by {account.name}",
    )


def scheduled_jobs_hour(environment: SimulationEnvironment, hour_start: float) -> Case:
    rng = environment.rng
    cron = environment.services["cron"]
    sessions: list[str] = []
    for minute in range(0, 60, 5):
        timestamp = hour_start + minute * 60 + rng.uniform(0.0, 1.5)
        job = environment.system_session(ROOT)
        sessions.append(str(job.session))
        shell = job.run(timestamp, ["sh", "-c", "/usr/bin/python3 /opt/monitoring/healthcheck.py"], parent=cron)
        checker = job.run(timestamp + 0.05, ["python3", "/opt/monitoring/healthcheck.py"], parent=shell)
        environment.audit.connect(
            timestamp + 0.3, checker, shell.pid, MONITORING_SERVER, 9100, ["python3", "healthcheck.py"]
        )
    hourly = environment.system_session(ROOT)
    sessions.append(str(hourly.session))
    timestamp = hour_start + 17 * 60 + rng.uniform(0, 1)
    shell = hourly.run(timestamp, ["sh", "-c", "cd / && run-parts --report /etc/cron.hourly"], parent=cron)
    hourly.run(timestamp + 0.05, ["run-parts", "--report", "/etc/cron.hourly"], parent=shell)
    if int(hour_start // HOUR) % 24 == 6:
        timestamp = hour_start + 25 * 60
        rotate = hourly.run(timestamp, ["logrotate", "/etc/logrotate.conf"], parent=shell)
        for log_name in ("auth.log", "syslog"):
            environment.audit.rename(
                timestamp + 0.5,
                rotate,
                shell.pid,
                f"/var/log/{log_name}",
                f"/var/log/{log_name}.1",
                "lg_logs",
                ["logrotate"],
            )
        hourly.run(timestamp + 1.0, ["gzip", "/var/log/auth.log.2"], parent=rotate)
    if rng.random() < 0.3:
        php = environment.services["php-fpm"]
        convert = environment.service_process(WEB_SERVICE, "/usr/bin/convert-im6.q16")
        environment.audit.execution(
            hour_start + rng.uniform(0, HOUR),
            convert,
            php.pid,
            ["convert", "upload.png", "-resize", "800x", "thumb.png"],
            "/var/www/html",
        )
    return environment.add_case(
        "scheduled_jobs",
        False,
        hour_start,
        hour_start + HOUR,
        {"session_id": sessions, "user": [WEB_SERVICE.name]},
        None,
        "Scheduled maintenance jobs and service activity",
    )


def command_path(name: str) -> str:
    return COMMAND_PATHS.get(name, name)


def read_file(
    shell: ShellSession,
    process_arguments: list[str],
    path: str,
    timestamp: float,
    key: str,
    as_root: bool = False,
) -> None:
    process = shell.sudo(timestamp, process_arguments) if as_root else shell.run(timestamp, process_arguments)
    shell.environment.audit.file_open(
        timestamp + 0.05, process, shell.shell.pid, path, OPEN_READ, key, shell.cwd, process_arguments
    )
