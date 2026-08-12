"""Security policy for ARPIP Terminal Assistant.

The assistant is intentionally conservative.  A command must be a single,
read-only command from the allowlist, with no shell control operators and no
credential-oriented searches, before it can be offered for execution.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
import shlex


@dataclass(frozen=True)
class ValidationResult:
    """Result returned by validate_command."""

    allowed: bool
    reason: str
    command: str = ""
    tokens: tuple[str, ...] = ()


ALLOWED_COMMANDS = {
    "dir",
    "du",
    "file",
    "find",
    "findstr",
    "ls",
    "rg",
    "ripgrep",
    "stat",
    "tree",
    "wc",
    "where",
}

SHELLS_AND_INTERPRETERS = {
    "bash",
    "cmd",
    "fish",
    "node",
    "npm",
    "npx",
    "perl",
    "powershell",
    "pwsh",
    "py",
    "python",
    "python3",
    "ruby",
    "sh",
    "wsl",
    "zsh",
}

FORBIDDEN_CHARACTERS = set("&;|<>`\n\r")
FORBIDDEN_SUBSTRINGS = ("$(", "${")

DANGEROUS_TOKENS = {
    "attrib",
    "chgrp",
    "chmod",
    "chown",
    "copy",
    "cp",
    "del",
    "delete",
    "diskpart",
    "erase",
    "fdisk",
    "format",
    "icacls",
    "kill",
    "mkfs",
    "move",
    "mv",
    "net",
    "reboot",
    "reg",
    "restart",
    "rm",
    "rmdir",
    "runas",
    "sc",
    "shutdown",
    "sudo",
    "su",
    "takeown",
    "taskkill",
    "xcopy",
}

DANGEROUS_FIND_ACTIONS = {
    "-delete",
    "-exec",
    "-execdir",
    "-fls",
    "-fprint",
    "-fprintf",
    "-ok",
    "-okdir",
}

SENSITIVE_PATTERNS = (
    re.compile(r"\.env(?:\.|$|[/\\])", re.IGNORECASE),
    re.compile(r"(?:^|[._\-/\\])api[_-]?key(?:$|[._\-/\\])", re.IGNORECASE),
    re.compile(r"(?:^|[._\-/\\])credential(?:s)?(?:$|[._\-/\\])", re.IGNORECASE),
    re.compile(r"(?:^|[._\-/\\])id_(?:rsa|dsa|ecdsa|ed25519)(?:$|[._\-/\\])", re.IGNORECASE),
    re.compile(r"(?:^|[._\-/\\])pass(?:word|wd)?(?:$|[._\-/\\])", re.IGNORECASE),
    re.compile(r"(?:^|[._\-/\\])private[_-]?key(?:$|[._\-/\\])", re.IGNORECASE),
    re.compile(r"(?:^|[._\-/\\])secret(?:s)?(?:$|[._\-/\\])", re.IGNORECASE),
    re.compile(r"(?:^|[._\-/\\])token(?:s)?(?:$|[._\-/\\])", re.IGNORECASE),
    re.compile(r"(?:^|[/\\])\.ssh(?:$|[/\\])", re.IGNORECASE),
    re.compile(r"(?:^|[/\\])\.aws(?:$|[/\\])", re.IGNORECASE),
    re.compile(r"(?:^|[/\\])\.azure(?:$|[/\\])", re.IGNORECASE),
    re.compile(r"(?:^|[/\\])\.config[/\\]gcloud(?:$|[/\\])", re.IGNORECASE),
    re.compile(r"/etc/(?:passwd|shadow|sudoers)\b", re.IGNORECASE),
    re.compile(r"windows[/\\]system32[/\\]config", re.IGNORECASE),
)


def validate_command(command: str) -> ValidationResult:
    """Validate that command is a single safe read-only command.

    The validation intentionally rejects many technically read-only commands if
    they are outside the narrow initial scope.  This is safer than trying to
    prove arbitrary shell text is harmless.
    """

    if not isinstance(command, str):
        return _reject("Command must be text.")

    command = command.strip()
    if not command:
        return _reject("Command is empty.")
    if len(command) > 500:
        return _reject("Command is too long for the restricted policy.")

    for character in FORBIDDEN_CHARACTERS:
        if character in command:
            return _reject(
                "Command chaining, pipes, redirection, backticks, and newlines are not allowed."
            )
    if any(fragment in command for fragment in FORBIDDEN_SUBSTRINGS):
        return _reject("Shell substitution syntax is not allowed.")

    tokens = _split_command(command)
    if not tokens:
        return _reject("Command could not be parsed.")

    base_command = _base_command(tokens[0])
    if base_command in SHELLS_AND_INTERPRETERS:
        return _reject("Shells and interpreters are not allowed.")
    if base_command not in ALLOWED_COMMANDS:
        return _reject(f"'{base_command}' is outside the restricted allowlist.")

    for token in tokens:
        if _base_command(token) in DANGEROUS_TOKENS:
            return _reject("Dangerous, destructive, or privilege-related command terms are not allowed.")
        if _looks_sensitive(token):
            return _reject("Credential, password, token, key, or secret access is not allowed.")

    validator = _VALIDATORS[base_command]
    ok, reason = validator(tokens)
    if not ok:
        return _reject(reason)

    return ValidationResult(
        allowed=True,
        reason="Command passed the restricted read-only allowlist.",
        command=base_command,
        tokens=tuple(tokens),
    )


def execution_args(command: str, validation: ValidationResult) -> list[str]:
    """Return subprocess arguments for an already validated command.

    subprocess is always called with shell=False.  Windows `dir` is a cmd.exe
    built-in, so it is run through cmd.exe only after the original `dir` command
    passes the strict single-command safety policy.
    """

    if not validation.allowed:
        raise ValueError("Refusing to prepare an unsafe command.")
    if validation.command == "dir" and os.name == "nt":
        return ["cmd.exe", "/d", "/c", command.strip()]
    return list(validation.tokens)


def _reject(reason: str) -> ValidationResult:
    return ValidationResult(allowed=False, reason=reason)


def _split_command(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=os.name != "nt")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return [_strip_outer_quotes(token) for token in lexer]
    except ValueError:
        return []


def _strip_outer_quotes(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        return token[1:-1]
    return token


def _base_command(token: str) -> str:
    cleaned = _strip_outer_quotes(token).strip().replace("\\", "/").rstrip("/")
    base = cleaned.rsplit("/", 1)[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def _looks_sensitive(token: str) -> bool:
    normalized = _strip_outer_quotes(token).replace("\\", "/")
    return any(pattern.search(normalized) for pattern in SENSITIVE_PATTERNS)


def _validate_ls(tokens: list[str]) -> tuple[bool, str]:
    long_flags = {
        "--all",
        "--almost-all",
        "--classify",
        "--directory",
        "--human-readable",
        "--long",
        "--recursive",
        "--reverse",
        "--size",
    }
    allowed_short = set("1aAcdFhlRrS")
    for token in tokens[1:]:
        if token.startswith("--"):
            if token.startswith("--color="):
                if token.split("=", 1)[1] not in {"always", "auto", "never"}:
                    return False, "Unsupported ls --color value."
            elif token not in long_flags:
                return False, f"Unsupported ls option: {token}"
        elif token.startswith("-") and token != "-":
            if not set(token[1:]).issubset(allowed_short):
                return False, f"Unsupported ls option: {token}"
    return True, "ok"


def _validate_dir(tokens: list[str]) -> tuple[bool, str]:
    allowed_windows_options = ("/a", "/b", "/d", "/l", "/n", "/o", "/p", "/q", "/s", "/t", "/w", "/x", "/4")
    for token in tokens[1:]:
        lowered = token.lower()
        if lowered.startswith("/") and not lowered.startswith(allowed_windows_options):
            # Treat Unix absolute paths as paths, not dir.exe flags.
            if not lowered.startswith(("/home", "/tmp", "/users", "/var", "/usr", "/opt", "/.")):
                return False, f"Unsupported dir option: {token}"
    return _validate_ls_style_short_flags(tokens, set("1aAcdFhlRrS"), "dir")


def _validate_tree(tokens: list[str]) -> tuple[bool, str]:
    allowed = {"/a", "/f", "-a", "-d", "-f"}
    i = 1
    while i < len(tokens):
        token = tokens[i]
        lowered = token.lower()
        if lowered in {"-l", "--level"}:
            if i + 1 >= len(tokens) or not tokens[i + 1].isdigit():
                return False, "tree depth option requires a numeric value."
            i += 2
            continue
        if (token.startswith("-") or token.startswith("/")) and lowered not in allowed:
            return False, f"Unsupported tree option: {token}"
        i += 1
    return True, "ok"


def _validate_rg(tokens: list[str]) -> tuple[bool, str]:
    no_value_flags = {
        "--case-sensitive",
        "--count",
        "--files",
        "--files-with-matches",
        "--fixed-strings",
        "--heading",
        "--ignore-case",
        "--json",
        "--line-number",
        "--no-heading",
        "--no-messages",
        "--smart-case",
        "--stats",
        "--word-regexp",
    }
    value_flags = {
        "--glob",
        "--max-count",
        "--max-depth",
        "--max-filesize",
        "--sort",
        "--type",
        "--type-not",
    }
    short_no_value = set("cFHhIilnSsw")
    short_value = {"-e", "-g", "-m", "-t", "-T"}
    blocked_prefixes = ("--pre", "--search-zip", "--unrestricted", "--follow")

    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token == "--":
            return False, "The -- argument separator is not allowed."
        if token.startswith(blocked_prefixes) or token in {"-u", "-uu", "-uuu", "-L", "-z"}:
            return False, f"Unsupported ripgrep option: {token}"
        if token in no_value_flags:
            i += 1
            continue
        if token in value_flags or token in short_value:
            if i + 1 >= len(tokens):
                return False, f"{token} requires a value."
            i += 2
            continue
        if any(token.startswith(flag + "=") for flag in value_flags):
            i += 1
            continue
        if any(token.startswith(flag) and len(token) > len(flag) for flag in short_value):
            i += 1
            continue
        if token.startswith("-"):
            if len(token) == 1 or not set(token[1:]).issubset(short_no_value):
                return False, f"Unsupported ripgrep option: {token}"
        i += 1
    return True, "ok"


def _validate_find(tokens: list[str]) -> tuple[bool, str]:
    value_options = {
        "-iname",
        "-maxdepth",
        "-mindepth",
        "-mmin",
        "-mtime",
        "-name",
        "-path",
        "-size",
        "-type",
    }
    no_value_options = {"!", "(", ")", "-a", "-and", "-not", "-o", "-or", "-print"}
    i = 1
    while i < len(tokens):
        token = tokens[i]
        lowered = token.lower()
        if lowered in DANGEROUS_FIND_ACTIONS:
            return False, f"Dangerous find action is not allowed: {token}"
        if lowered in value_options:
            if i + 1 >= len(tokens):
                return False, f"{token} requires a value."
            value = tokens[i + 1]
            if lowered in {"-maxdepth", "-mindepth"} and not value.isdigit():
                return False, f"{token} requires a numeric value."
            if lowered == "-type" and value not in {"d", "f", "l"}:
                return False, "find -type is limited to f, d, or l."
            if lowered == "-size" and not re.fullmatch(r"[+-]?\d+[bcwkMG]?", value):
                return False, "find -size uses an unsupported value."
            i += 2
            continue
        if lowered in no_value_options:
            i += 1
            continue
        if token.startswith("-"):
            return False, f"Unsupported find option: {token}"
        i += 1
    return True, "ok"


def _validate_findstr(tokens: list[str]) -> tuple[bool, str]:
    allowed_flags = {"/b", "/e", "/i", "/l", "/m", "/n", "/p", "/r", "/s", "/x"}
    for token in tokens[1:]:
        lowered = token.lower()
        if lowered.startswith("/c:"):
            if len(token) <= 3:
                return False, "findstr /C requires a search string."
            continue
        if lowered.startswith("/") and lowered not in allowed_flags:
            return False, f"Unsupported findstr option: {token}"
    return True, "ok"


def _validate_where(tokens: list[str]) -> tuple[bool, str]:
    i = 1
    while i < len(tokens):
        lowered = tokens[i].lower()
        if lowered == "/r":
            if i + 1 >= len(tokens):
                return False, "where /R requires a directory value."
            i += 2
            continue
        if lowered.startswith("/") and lowered not in {"/f", "/q", "/t"}:
            return False, f"Unsupported where option: {tokens[i]}"
        i += 1
    return True, "ok"


def _validate_stat(tokens: list[str]) -> tuple[bool, str]:
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token in {"-c", "-f"}:
            if i + 1 >= len(tokens):
                return False, f"{token} requires a format value."
            i += 2
            continue
        if token.startswith("-"):
            return False, f"Unsupported stat option: {token}"
        i += 1
    return True, "ok"


def _validate_file(tokens: list[str]) -> tuple[bool, str]:
    allowed = {"-b", "-h", "--brief", "--no-dereference"}
    for token in tokens[1:]:
        if token.startswith("-") and token not in allowed:
            return False, f"Unsupported file option: {token}"
    return True, "ok"


def _validate_du(tokens: list[str]) -> tuple[bool, str]:
    return _validate_ls_style_short_flags(tokens, set("achs"), "du")


def _validate_wc(tokens: list[str]) -> tuple[bool, str]:
    return _validate_ls_style_short_flags(tokens, set("clmw"), "wc")


def _validate_ls_style_short_flags(tokens: list[str], allowed_short: set[str], name: str) -> tuple[bool, str]:
    for token in tokens[1:]:
        if token.startswith("--"):
            return False, f"Unsupported {name} option: {token}"
        if token.startswith("-") and token != "-":
            if not set(token[1:]).issubset(allowed_short):
                return False, f"Unsupported {name} option: {token}"
    return True, "ok"


_VALIDATORS = {
    "dir": _validate_dir,
    "du": _validate_du,
    "file": _validate_file,
    "find": _validate_find,
    "findstr": _validate_findstr,
    "ls": _validate_ls,
    "rg": _validate_rg,
    "ripgrep": _validate_rg,
    "stat": _validate_stat,
    "tree": _validate_tree,
    "wc": _validate_wc,
    "where": _validate_where,
}
