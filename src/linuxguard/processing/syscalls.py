X86_64_ARCH = "c000003e"
AARCH64_ARCH = "c00000b7"

_X86_64_SYSCALLS = {
    2: "open",
    42: "connect",
    59: "execve",
    76: "truncate",
    77: "ftruncate",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    94: "lchown",
    101: "ptrace",
    105: "setuid",
    106: "setgid",
    113: "setreuid",
    114: "setregid",
    117: "setresuid",
    119: "setresgid",
    175: "init_module",
    176: "delete_module",
    257: "openat",
    258: "mkdirat",
    260: "fchownat",
    263: "unlinkat",
    264: "renameat",
    265: "linkat",
    266: "symlinkat",
    268: "fchmodat",
    313: "finit_module",
    316: "renameat2",
    322: "execveat",
    437: "openat2",
    452: "fchmodat2",
}

_AARCH64_SYSCALLS = {
    34: "mkdirat",
    35: "unlinkat",
    36: "symlinkat",
    37: "linkat",
    38: "renameat",
    45: "truncate",
    46: "ftruncate",
    52: "fchmod",
    53: "fchmodat",
    54: "fchownat",
    55: "fchown",
    56: "openat",
    105: "init_module",
    106: "delete_module",
    117: "ptrace",
    143: "setregid",
    144: "setgid",
    145: "setreuid",
    146: "setuid",
    147: "setresuid",
    149: "setresgid",
    203: "connect",
    221: "execve",
    273: "finit_module",
    276: "renameat2",
    281: "execveat",
    437: "openat2",
    452: "fchmodat2",
}

_TABLES = {X86_64_ARCH: _X86_64_SYSCALLS, AARCH64_ARCH: _AARCH64_SYSCALLS}

EXECUTION_SYSCALLS = frozenset({"execve", "execveat"})
OPEN_SYSCALLS = frozenset({"open", "openat", "openat2", "creat"})
MODIFICATION_SYSCALLS = frozenset(
    {
        "truncate",
        "ftruncate",
        "rename",
        "renameat",
        "renameat2",
        "unlink",
        "unlinkat",
        "rmdir",
        "mkdir",
        "mkdirat",
        "link",
        "linkat",
        "symlink",
        "symlinkat",
    }
)
CHMOD_SYSCALLS = frozenset({"chmod", "fchmod", "fchmodat", "fchmodat2"})
CHOWN_SYSCALLS = frozenset({"chown", "fchown", "lchown", "fchownat"})
MODULE_SYSCALLS = frozenset({"init_module", "finit_module", "delete_module"})
IDENTITY_SYSCALLS = frozenset({"setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid"})
NETWORK_SYSCALLS = frozenset({"connect"})

OPEN_FLAGS_ARGUMENT = {"open": "a1", "openat": "a2", "creat": None, "openat2": None}
CHMOD_MODE_ARGUMENT = {"chmod": "a1", "fchmod": "a1", "fchmodat": "a2", "fchmodat2": "a2"}

WRITE_ACCESS_MASK = 0o3
CREATE_FLAG = 0o100
TRUNCATE_FLAG = 0o1000
SPECIAL_MODE_MASK = 0o7000


def resolve_syscall_name(arch: str | None, syscall: str | None) -> str | None:
    if syscall is None:
        return None
    if not syscall.isdigit():
        return syscall
    table = _TABLES.get((arch or X86_64_ARCH).lower(), _X86_64_SYSCALLS)
    return table.get(int(syscall), f"syscall_{syscall}")


def is_write_open(flags: int) -> bool:
    return bool(flags & WRITE_ACCESS_MASK) or bool(flags & (CREATE_FLAG | TRUNCATE_FLAG))
