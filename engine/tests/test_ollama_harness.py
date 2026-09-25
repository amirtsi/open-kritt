import json
import os

import pytest

from open_kritt_engine.harnesses import HarnessError, OllamaHarness, harness_for


def test_ollama_harness_parses_text_tool_calls_and_returns_final_payload(tmp_path, monkeypatch):
    (tmp_path / "go.mod").write_text("module github.com/example/repo\n\ngo 1.24\n", encoding="utf-8")
    replies = iter(
        [
            {"message": {"content": '<tool_call>{"name":"read_file","arguments":{"path":"go.mod","line_count":1}}</tool_call>'}},
            {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "module inspected",
                            "module": "github.com/example/repo",
                        }
                    )
                },
                "prompt_eval_count": 10,
                "eval_count": 4,
            },
        ]
    )
    observed = []
    harness = OllamaHarness(timeout_seconds=5, model_provider="ollama")

    def fake_chat(_base_url, payload, _timeout_seconds=None):
        observed.append(payload)
        return next(replies)

    monkeypatch.setattr(harness, "_chat", fake_chat)
    result = harness.run(
        prompt="Inspect the module.",
        schema={
            "type": "object",
            "properties": {"summary": {"type": "string"}, "module": {"type": "string"}},
            "required": ["summary", "module"],
        },
        repo_dir=str(tmp_path),
        model="qwen2.5-coder:7b-instruct",
    )

    assert result.payload == {"summary": "module inspected", "module": "github.com/example/repo"}
    assert result.usage["local"] is True
    assert "github.com/example/repo" in observed[1]["messages"][-1]["content"]


def test_ollama_harness_rejects_paths_outside_repository(tmp_path):
    harness = OllamaHarness(timeout_seconds=5)
    with pytest.raises(HarnessError, match="outside the repository"):
        harness._tool(str(tmp_path), "read_file", {"path": "../secret"})


def test_ollama_harness_uses_explicit_environment_without_ambient_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://ambient.invalid")
    harness = OllamaHarness(timeout_seconds=5)
    observed = []

    def fake_chat(base_url, _payload, _timeout_seconds=None):
        observed.append(base_url)
        return {"message": {"content": '{"summary":"done"}'}}

    monkeypatch.setattr(harness, "_chat", fake_chat)
    result = harness.run(
        prompt="Return the result.",
        schema={"type": "object", "properties": {"summary": {"type": "string"}}},
        repo_dir=str(tmp_path),
        model="qwen2.5-coder:7b-instruct",
        env={},
        allow_tools=False,
    )

    assert result.payload == {"summary": "done"}
    assert observed == ["http://host.docker.internal:11435"]


def test_ollama_search_falls_back_when_ripgrep_is_unavailable(tmp_path, monkeypatch):
    (tmp_path / "contract.sol").write_text("contract Safe {}\ncontract Target {}\n", encoding="utf-8")
    harness = OllamaHarness(timeout_seconds=5)
    monkeypatch.setattr("open_kritt_engine.harnesses.shutil.which", lambda _name: None)

    result = harness._tool(str(tmp_path), "search_text", {"pattern": "Target", "path": "."})

    assert result == "contract.sol:2:contract Target {}"


def test_harness_factory_supports_ollama():
    harness = harness_for("ollama", timeout_seconds=5, model_provider="ollama")
    assert isinstance(harness, OllamaHarness)


@pytest.mark.skipif(os.getenv("OLLAMA_INTEGRATION") != "1", reason="requires the isolated local Ollama server")
def test_ollama_harness_live_repository_round_trip(tmp_path):
    (tmp_path / "go.mod").write_text("module github.com/example/live-bridge\n\ngo 1.24\n", encoding="utf-8")
    harness = OllamaHarness(timeout_seconds=180, model_provider="ollama")
    result = harness.run(
        prompt=(
            "Read go.mod with the provided tool. Then return only a JSON object with "
            'summary set to "module inspected" and module set to the module path you observed.'
        ),
        schema={
            "type": "object",
            "properties": {"summary": {"type": "string"}, "module": {"type": "string"}},
            "required": ["summary", "module"],
            "additionalProperties": False,
        },
        repo_dir=str(tmp_path),
        model=os.getenv("OLLAMA_INTEGRATION_MODEL", "qwen2.5-coder:7b-instruct"),
        env={"OLLAMA_BASE_URL": os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11435")},
    )

    assert result.payload == {"summary": "module inspected", "module": "github.com/example/live-bridge"}
    assert result.usage["local"] is True
