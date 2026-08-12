"""ARPIP Terminal Assistant CLI.

Converts natural-language requests into one proposed terminal command, validates
the command, and executes only after explicit human confirmation.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys

from backboard import BackboardClient

from safety import execution_args, validate_command


SYSTEM_PROMPT = """
You are ARPIP Terminal Assistant, a command proposal engine for a safe CLI.

Return exactly one terminal command for the user's request.
Rules:
- Output only JSON in this exact shape: {"command":"..."}
- The command must be a single read-only command.
- Prefer safe commands for listing files/directories, finding files by name/type/size,
  checking file metadata, or searching text in files.
- Do not include explanations, markdown, code fences, comments, or multiple commands.
- Do not use command chaining, pipes, redirection, shell substitution, or newlines.
- Do not propose destructive, privilege-escalation, credential-access, arbitrary shell,
  PowerShell, or interpreter commands.
- If the user asks for an unsafe or unsupported operation, return {"command":""}.
""".strip()

MODEL_PROVIDER = os.getenv("BACKBOARD_LLM_PROVIDER", "openai")
MODEL_NAME = os.getenv("BACKBOARD_MODEL_NAME", "gpt-4o")
COMMAND_TIMEOUT_SECONDS = 30


async def generate_command(client: BackboardClient, user_request: str) -> str:
    """Ask Backboard for exactly one proposed command."""

    response = await client.send_message(
        user_request,
        system_prompt=SYSTEM_PROMPT,
        llm_provider=MODEL_PROVIDER,
        model_name=MODEL_NAME,
        memory="off",
        web_search="off",
        json_output=True,
    )
    return extract_command(response.content)


def extract_command(content: str) -> str:
    """Extract the command from the SDK response content."""

    if not content:
        return ""

    text = content.strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            return text.splitlines()[0].strip()
        try:
            payload = json.loads(match.group(0))
        except json.JSONDecodeError:
            return ""

    if isinstance(payload, dict):
        command = payload.get("command", "")
        return command.strip() if isinstance(command, str) else ""
    return ""


def display_command(command: str) -> None:
    print("\nProposed command:")
    print("-----------------")
    print(command or "<no safe command proposed>")
    print("-----------------")


def ask_for_confirmation() -> bool:
    answer = input('Execute this command? [YES/NO] ').strip()
    return answer == "YES"


def execute_command(command: str) -> int:
    validation = validate_command(command)
    if not validation.allowed:
        print(f"Safety validation failed: {validation.reason}")
        return 1

    args = execution_args(command, validation)
    print("\nExecuting...\n")
    try:
        completed = subprocess.run(
            args,
            shell=False,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        print(f"Command is allowlisted but not available on this system: {validation.command}")
        return 1
    except subprocess.TimeoutExpired:
        print(f"Command timed out after {COMMAND_TIMEOUT_SECONDS} seconds.")
        return 1

    return completed.returncode


async def interactive_loop() -> int:
    api_key = os.getenv("BACKBOARD_API_KEY")
    if not api_key:
        print("BACKBOARD_API_KEY is required. Set it in your environment and try again.")
        return 1

    client = BackboardClient(api_key=api_key)

    print("ARPIP Terminal Assistant")
    print("Type a request, or type 'exit' to quit.")
    print("Commands are never executed unless you enter YES exactly.\n")

    while True:
        try:
            user_request = input("Request> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            return 0

        if not user_request:
            continue
        if user_request.lower() in {"exit", "quit"}:
            print("Exiting.")
            return 0

        try:
            command = await generate_command(client, user_request)
        except Exception as exc:  # noqa: BLE001 - CLI should show a concise failure.
            print(f"Backboard request failed: {exc}")
            continue

        display_command(command)
        validation = validate_command(command)
        if not validation.allowed:
            print(f"Safety validation failed: {validation.reason}")
            print("Nothing was executed.\n")
            continue

        print(f"Safety validation passed: {validation.reason}")
        if ask_for_confirmation():
            code = execute_command(command)
            print(f"\nCommand exited with status {code}.\n")
        else:
            print("Nothing was executed.\n")


def main() -> int:
    return asyncio.run(interactive_loop())


if __name__ == "__main__":
    sys.exit(main())
