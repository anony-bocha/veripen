import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from veripen.benchmarks.vulhub_runner import VulHubRunner
from veripen.core.schemas import (
    ExploitClaim,
    VulnerabilityType,
    InjectionPoint
)

def test_compose_command_execution(tmp_path):
    runner = VulHubRunner(vulhub_root=str(tmp_path))
    dummy_dir = tmp_path / "test_app"
    dummy_dir.mkdir()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        success = runner._run_compose_cmd(dummy_dir, ["up", "-d"])
        assert success is True
        mock_run.assert_called_once()
