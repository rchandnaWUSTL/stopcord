import json
import os
import subprocess
import sys

from conftest import NETBLOCK

from stopcord.chain import read_entries, verify


def test_demo_runs_offline_and_verifies(isolated):
    env = {**os.environ, "PYTHONPATH": str(NETBLOCK), "STOPCORD_SCRIPTED_DELAY": "0"}
    proc = subprocess.run(
        [sys.executable, "-m", "stopcord.cli", "demo", "--fast", "--no-open"],
        cwd=isolated, env=env, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[scripted agent]" in proc.stdout
    logs = list((isolated / "runs").glob("*.jsonl"))
    assert len(logs) == 1
    assert verify(logs[0]).ok
    entries = read_entries(logs[0])
    denied = [(e["tool"], e["target"], e["rule_id"]) for e in entries if e["decision"] == "deny"]
    assert denied == [("read_file", ".env", "env-files"), ("http_request", "attacker.example", "no-egress")]
    assert entries[-1]["event"] == "run_finished"
    assert entries[-1]["detail"]["exit_code"] == 0
    # the agent's summary was saved next to the log and bound to it by hash
    summary = logs[0].with_suffix(".summary.txt")
    import hashlib
    assert entries[-1]["detail"]["agent_summary_sha256"] == hashlib.sha256(summary.read_bytes()).hexdigest()
    # the fix actually landed: the second pytest run passed
    results = [e for e in entries if e["event"] == "tool_result" and e["tool"] == "run_command"]
    assert results[-2]["result_preview"].startswith("exit code 0")


def test_netblock_actually_blocks(isolated):
    env = {**os.environ, "PYTHONPATH": str(NETBLOCK)}
    code = "import socket; s=socket.socket(); s.connect(('93.184.215.14', 80))"
    proc = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
    assert "network blocked in test" in proc.stderr
