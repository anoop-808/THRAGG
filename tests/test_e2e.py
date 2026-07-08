import os
import subprocess
import json
from pathlib import Path

def test_e2e_sample_evidence_pipeline(tmp_path):
    output_dir = tmp_path / "thragg_results"
    
    # Run the orchestrator directly using subprocess
    result = subprocess.run(
        ["python", "thragg.py", "sample_evidence"],
        cwd=str(Path(__file__).parent.parent),
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0
    assert "[THRAGG] Pipeline complete." in result.stdout
    assert "Modules failed : 0" in result.stdout
    
    # Verify outputs
    results_path = Path(__file__).parent.parent / "thragg_results"
    html_files = list(results_path.glob("*.html"))
    json_files = list(results_path.glob("*.json"))
    
    assert any(f.name == "dashboard.html" for f in html_files)
    assert len(json_files) > 0


def test_e2e_empty_directory(tmp_path):
    empty_dir = tmp_path / "empty_evidence"
    empty_dir.mkdir()
    
    result = subprocess.run(
        ["python", "thragg.py", str(empty_dir)],
        cwd=str(Path(__file__).parent.parent),
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0
    assert "Files analyzed : 0" in result.stdout


def test_e2e_corrupted_evidence(tmp_path):
    corrupt_dir = tmp_path / "corrupt_evidence"
    corrupt_dir.mkdir()
    
    # Create a corrupted users.json
    corrupt_file = corrupt_dir / "users.json"
    corrupt_file.write_text("{badjson")
    
    result = subprocess.run(
        ["python", "thragg.py", str(corrupt_dir)],
        cwd=str(Path(__file__).parent.parent),
        capture_output=True,
        text=True
    )
    
    # Pipeline should still complete, but log the module failure
    assert result.returncode == 0
    assert "Modules failed : 1" in result.stdout
    assert "Invalid JSON" in result.stderr
