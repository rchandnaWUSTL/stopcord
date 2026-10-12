import json

import pytest

from stopcord.chain import ChainWriter, canonical_json, verify


def write_log(path, n_calls=5):
    w = ChainWriter(path, "r-test", "ab" * 32, "0.1.0")
    w.append("run_started", detail={"policy_sha256": "ab" * 32, "gateway_version": "0.1.0"})
    for i in range(n_calls):
        w.append("tool_requested", tool="read_file", args={"path": f"f{i}.py"}, target=f"f{i}.py")
        w.append("policy_decision", tool="read_file", rule_id="workspace-files", decision="allow")
        w.append("tool_result", tool="read_file", result_digest="sha256:00", summary="ok ✓")
    w.append("run_finished", summary="done")
    w.close()
    return path


def test_clean_log_verifies(tmp_path):
    log = write_log(tmp_path / "r.jsonl")
    r = verify(log)
    assert r.ok and r.entries == 17 and r.head == json.loads(log.read_text().splitlines()[-1])["hash"]


def test_policy_hash_is_checked(tmp_path):
    log = write_log(tmp_path / "r.jsonl")
    assert verify(log, policy_sha256="ab" * 32).ok
    r = verify(log, policy_sha256="cd" * 32)
    assert not r.ok and r.broken_seq == 1


def test_every_single_byte_flip_is_caught_at_its_entry(tmp_path):
    """Flip every byte of every entry, one at a time. Each must fail at that entry."""
    log = write_log(tmp_path / "r.jsonl", n_calls=2)
    original = log.read_bytes()
    offsets = []
    pos = 0
    for n, line in enumerate(original.split(b"\n")[:-1], start=1):
        offsets.extend((pos + i, n) for i in range(len(line)))
        pos += len(line) + 1
    for off, n in offsets:
        b = bytearray(original)
        b[off] ^= 0x01
        log.write_bytes(bytes(b))
        r = verify(log)
        assert not r.ok, f"flip at byte {off} (entry {n}) went unnoticed"
        assert r.broken_seq == n, f"flip in entry {n} reported at {r.broken_seq}: {r.reason}"


def test_deleted_entry_is_caught(tmp_path):
    log = write_log(tmp_path / "r.jsonl")
    lines = log.read_text().splitlines()
    del lines[6]
    log.write_text("\n".join(lines) + "\n")
    r = verify(log)
    assert not r.ok and r.broken_seq == 7


def test_reordered_entries_are_caught(tmp_path):
    log = write_log(tmp_path / "r.jsonl")
    lines = log.read_text().splitlines()
    lines[3], lines[4] = lines[4], lines[3]
    log.write_text("\n".join(lines) + "\n")
    r = verify(log)
    assert not r.ok and r.broken_seq == 4


def test_rehashed_edit_still_breaks_the_next_link(tmp_path):
    """Editing an entry and fixing its own hash breaks the following entry's prev_hash."""
    from stopcord.chain import entry_hash

    log = write_log(tmp_path / "r.jsonl")
    lines = log.read_text().splitlines()
    e = json.loads(lines[5])
    e["decision"] = "deny"
    e["hash"] = entry_hash(e)
    lines[5] = canonical_json(e)
    log.write_text("\n".join(lines) + "\n")
    r = verify(log)
    assert not r.ok and r.broken_seq == 7


def test_truncation_warns(tmp_path):
    log = write_log(tmp_path / "r.jsonl")
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:-1]) + "\n")
    r = verify(log)
    assert r.ok
    assert any("no run_finished" in w for w in r.warnings)


def test_writer_refuses_to_overwrite(tmp_path):
    log = write_log(tmp_path / "r.jsonl")
    with pytest.raises(FileExistsError):
        ChainWriter(log, "r-test", "ab" * 32, "0.1.0")
