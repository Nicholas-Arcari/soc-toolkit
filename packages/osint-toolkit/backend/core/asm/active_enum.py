"""Active subdomain enumeration via Amass / Subfinder subprocess wrappers.

Active means *we* talk to infrastructure that may be observable by the
target (DNS brute-force, HTTP probes, zone walks). That's legitimate
inside an authorized engagement and absolutely off-limits against a
random domain, which is why the flow is guarded on two axes:

* ``settings.enable_active_scanning`` - operator-level opt-in, set in
  the environment. Off by default.
* Per-scan confirmation token typed by the analyst - the request body
  must carry the target's ``name`` verbatim. Mirrors the "type the repo
  name to delete it" pattern used by GitHub, Heroku, and friends.

We detect-and-use the binaries instead of bundling them - Amass is
Apache 2.0 / Go, Subfinder is MIT / Go, both ship as static binaries.
Users who want active enum install one of them from their package
manager; users who don't get a clear "binary not found" error instead
of a half-broken experience.
"""
from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass, field


class ActiveScannerUnavailableError(RuntimeError):
    """No active-scan binary (Amass/Subfinder) found on PATH."""


@dataclass
class ActiveEnumResult:
    """Outcome of one active-enumeration run."""

    tool: str
    discovered: list[str] = field(default_factory=list)
    stderr: str = ""
    returncode: int = 0


def _detect_tool() -> str | None:
    """Prefer Subfinder (faster, MIT) - fall back to Amass when only it's installed."""
    for candidate in ("subfinder", "amass"):
        if shutil.which(candidate):
            return candidate
    return None


async def active_enumerate(
    root: str,
    *,
    tool: str | None = None,
    timeout: float = 120.0,
) -> ActiveEnumResult:
    """Run the chosen tool against ``root`` and return discovered FQDNs.

    ``tool`` defaults to the first available binary on PATH. Pass
    explicitly to force a particular one (useful for tests or when an
    operator wants deterministic output).

    ``timeout`` is enforced per invocation - active tools can hang on
    unreachable NS servers, and a stuck scan shouldn't wedge the API.
    """
    chosen = tool or _detect_tool()
    if chosen is None:
        raise ActiveScannerUnavailableError(
            "no active-scan binary found; install 'subfinder' (MIT) or 'amass' (Apache 2.0)"
        )

    args = _build_argv(chosen, root)
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return ActiveEnumResult(
            tool=chosen,
            discovered=[],
            stderr=f"{chosen} timed out after {timeout}s",
            returncode=124,
        )

    # Both tools stream one FQDN per line on stdout in their default modes.
    discovered = sorted(
        {
            line.strip().lower().rstrip(".")
            for line in stdout.decode("utf-8", errors="replace").splitlines()
            if line.strip() and not line.startswith("[")  # strip amass banner lines
        }
    )
    return ActiveEnumResult(
        tool=chosen,
        discovered=discovered,
        stderr=stderr.decode("utf-8", errors="replace"),
        returncode=proc.returncode or 0,
    )


def _build_argv(tool: str, root: str) -> list[str]:
    """Tool-specific argv - hidden behind a helper so callers don't branch."""
    if tool == "subfinder":
        # -silent: one FQDN per line, nothing else. Matches our parser.
        return ["subfinder", "-silent", "-d", root]
    if tool == "amass":
        # `amass enum -passive` is genuinely passive (it's what `amass enum`
        # without -active does). For "active" semantics callers expect
        # active probes, which is the default enum mode.
        return ["amass", "enum", "-d", root]
    raise ActiveScannerUnavailableError(f"unsupported tool {tool!r}")
