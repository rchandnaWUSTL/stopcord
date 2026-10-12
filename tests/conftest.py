import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
QUICKSTART = ROOT / "src/stopcord/quickstart"
NETBLOCK = Path(__file__).parent / "netblock"


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Run from a temp dir with its own state dir, so tests never touch runs/."""
    monkeypatch.chdir(tmp_path)
    state = tmp_path / "state"
    monkeypatch.setenv("STOPCORD_STATE_DIR", str(state))
    monkeypatch.setenv("STOPCORD_SCRIPTED_DELAY", "0")
    return tmp_path


def make_cfg(tmp_path, **kw):
    from stopcord.gateway import RunConfig, prepare_workspace

    cfg = RunConfig(
        policy_path=QUICKSTART / "policy.yaml",
        workspace=QUICKSTART / "workspace",
        runs_dir=tmp_path / "runs",
        work_root=tmp_path / "work",
        agent_label="test",
        **kw,
    )
    cfg.workspace = prepare_workspace(QUICKSTART / "workspace", cfg)
    return cfg


SCRIPTED = [sys.executable, "-m", "stopcord.agents.scripted"]
