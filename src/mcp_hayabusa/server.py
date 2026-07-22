"""MCP server exposing hayabusa's Windows event log analysis as tools."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import hayabusa

mcp = FastMCP(
    "hayabusa",
    instructions=(
        "Tools for analyzing Windows event log (.evtx) files with Hayabusa, "
        "a fast forensic timeline generator and threat hunting tool written "
        "in Rust. All tools shell out to a local hayabusa binary; set "
        "HAYABUSA_BIN to its full path if it is not already on PATH."
    ),
)


@mcp.tool()
def hayabusa_version() -> str:
    """Get the installed hayabusa binary's version string."""
    return hayabusa.version()


@mcp.tool()
def hayabusa_list_profiles() -> str:
    """List the output profiles available in this hayabusa installation."""
    return hayabusa.list_profiles()


@mcp.tool()
def hayabusa_update_rules() -> str:
    """Download or update hayabusa's Sigma detection rule set."""
    return hayabusa.update_rules()


@mcp.tool()
def hayabusa_csv_timeline(
    target: str,
    profile: str | None = None,
    min_level: str | None = None,
    rules_dir: str | None = None,
    max_rows: int = 200,
) -> dict:
    """Run hayabusa csv-timeline over an .evtx file or a directory of them.

    Produces a detection timeline and returns up to max_rows result rows
    plus the total row count so large results stay bounded.

    Args:
        target: Path to an .evtx file or a directory containing .evtx files.
        profile: Optional hayabusa output profile name (see
            hayabusa_list_profiles for available options).
        min_level: Optional minimum alert level to include, e.g.
            "informational", "low", "medium", "high", or "critical".
        rules_dir: Optional path to a custom Sigma rules directory.
        max_rows: Maximum number of result rows to return (default 200).
    """
    return hayabusa.csv_timeline(
        target,
        profile=profile,
        min_level=min_level,
        rules_dir=rules_dir,
        max_rows=max_rows,
    )


@mcp.tool()
def hayabusa_json_timeline(
    target: str,
    profile: str | None = None,
    min_level: str | None = None,
    rules_dir: str | None = None,
    max_rows: int = 200,
) -> dict:
    """Run hayabusa json-timeline over an .evtx file or a directory of them.

    Same behavior as hayabusa_csv_timeline but returns structured JSON
    detection records instead of CSV rows.
    """
    return hayabusa.json_timeline(
        target,
        profile=profile,
        min_level=min_level,
        rules_dir=rules_dir,
        max_rows=max_rows,
    )


@mcp.tool()
def hayabusa_eid_metrics(target: str, max_rows: int = 200) -> dict:
    """Count event occurrences by Event ID across .evtx file(s).

    Args:
        target: Path to an .evtx file or a directory containing .evtx files.
        max_rows: Maximum number of result rows to return (default 200).
    """
    return hayabusa.eid_metrics(target, max_rows=max_rows)


@mcp.tool()
def hayabusa_extract_base64(target: str, max_rows: int = 200) -> dict:
    """Extract and decode base64-encoded strings found in .evtx event fields.

    Useful for catching obfuscated PowerShell/command-line payloads.

    Args:
        target: Path to an .evtx file or a directory containing .evtx files.
        max_rows: Maximum number of result rows to return (default 200).
    """
    return hayabusa.extract_base64(target, max_rows=max_rows)


@mcp.tool()
def hayabusa_log_metrics(target: str, max_rows: int = 200) -> dict:
    """Output evtx file metadata (channels, event count, date range, etc.).

    Args:
        target: Path to an .evtx file or a directory containing .evtx files.
        max_rows: Maximum number of result rows to return (default 200).
    """
    return hayabusa.log_metrics(target, max_rows=max_rows)


@mcp.tool()
def hayabusa_computer_metrics(target: str, max_rows: int = 200) -> dict:
    """Count events per computer name across .evtx file(s).

    Args:
        target: Path to an .evtx file or a directory containing .evtx files.
        max_rows: Maximum number of result rows to return (default 200).
    """
    return hayabusa.computer_metrics(target, max_rows=max_rows)


@mcp.tool()
def hayabusa_logon_summary(target: str, max_rows: int = 200) -> dict:
    """Summarize successful and failed logon events across .evtx file(s).

    Returns two bounded result sets, "successful" and "failed", each with
    its own total_rows/returned_rows/truncated/rows.

    Args:
        target: Path to an .evtx file or a directory containing .evtx files.
        max_rows: Maximum number of rows to return per result set (default 200).
    """
    return hayabusa.logon_summary(target, max_rows=max_rows)


@mcp.tool()
def hayabusa_pivot_keywords_list(
    target: str,
    min_level: str | None = None,
    max_keywords: int = 200,
) -> dict:
    """Extract pivot keywords (users, computers, IPs, etc.) from .evtx file(s).

    Returns a dict of category name -> bounded keyword list, e.g.
    "Users", "IP Addresses", "Processes", "Command Lines" (categories
    come from hayabusa's pivot_keywords.txt config).

    Args:
        target: Path to an .evtx file or a directory containing .evtx files.
        min_level: Optional minimum alert level to include, e.g.
            "informational", "low", "medium", "high", or "critical".
        max_keywords: Maximum number of keywords to return per category
            (default 200).
    """
    return hayabusa.pivot_keywords_list(target, min_level=min_level, max_keywords=max_keywords)


@mcp.tool()
def hayabusa_config_critical_systems(target: str, max_hosts: int = 200) -> dict:
    """Find likely domain controllers and file servers from .evtx event logs.

    Detects domain controllers via Security EID 4768 (Kerberos TGT
    requests, only logged by DCs) and file servers via Security EID 5145
    (network share access, excluding the universal IPC$ share).

    Unlike other tools here, hayabusa has no file-output option for this
    subcommand and normally asks an interactive yes/no question about
    saving each found category to its local config. That prompt can't be
    answered non-interactively, so on a hit this call may take close to
    its timeout to return; when it does, prompt_interrupted will be true
    in the result and any category not present in "categories" was never
    reached, not confirmed as empty.

    Args:
        target: Path to an .evtx file or a directory containing .evtx files.
        max_hosts: Maximum number of hostnames to return per category
            (default 200).
    """
    return hayabusa.config_critical_systems(target, max_hosts=max_hosts)


@mcp.tool()
def hayabusa_search(
    target: str,
    keywords: list[str],
    regex: bool = False,
    max_rows: int = 200,
) -> dict:
    """Search .evtx event records for one or more keywords or regex patterns.

    Args:
        target: Path to an .evtx file or a directory containing .evtx files.
        keywords: Keywords (or regex patterns, if regex=True) to search for.
        regex: Treat keywords as regular expressions instead of literal strings.
        max_rows: Maximum number of matching rows to return (default 200).
    """
    return hayabusa.search(target, keywords, regex=regex, max_rows=max_rows)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
