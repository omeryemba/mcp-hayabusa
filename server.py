import json
import subprocess
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hayabusa-mcp-server")

HAYABUSA_EXECUTABLE = "hayabusa"


@mcp.tool()
def scan_evtx(file_path: str) -> str:
    """Scan a Windows EVTX file with Hayabusa and return the results."""
    evtx_path = Path(file_path)
    if not evtx_path.is_file():
        return json.dumps({"error": f"EVTX file not found: {file_path}"})

    try:
        with open(evtx_path, "rb"):
            pass
    except OSError as e:
        return json.dumps({"error": f"EVTX file is not readable: {e}"})

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "timeline.json"

        try:
            process = subprocess.run(
                [
                    HAYABUSA_EXECUTABLE,
                    "json-timeline",
                    "--no-wizard",
                    "-f", str(evtx_path),
                    "-o", str(output_path),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
            )
        except FileNotFoundError:
            return json.dumps({"error": f"Hayabusa executable not found: '{HAYABUSA_EXECUTABLE}'"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": "Hayabusa scan timed out"})

        if process.returncode != 0:
            return json.dumps({
                "error": "Hayabusa scan failed",
                "returncode": process.returncode,
                "stderr": process.stderr.strip(),
            })

        if not output_path.exists():
            return json.dumps({"error": "Hayabusa did not produce an output file"})

        output_text = output_path.read_text(encoding="utf-8").strip()

    if not output_text:
        return json.dumps({"results": []})

    try:
        results = json.loads(output_text)
    except json.JSONDecodeError:
        try:
            results = [json.loads(line) for line in output_text.splitlines() if line.strip()]
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid JSON output from Hayabusa: {e}"})

    return json.dumps(results)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
