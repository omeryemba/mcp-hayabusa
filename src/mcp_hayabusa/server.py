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
