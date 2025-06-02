import csv

from controlbench.adapters.claude import ClaudeDisabled, ClaudeMonitor, ClaudeUntrusted, extract_code
from controlbench.experiment import ExperimentConfig, pareto_table, run_experiment, write_csvs
from controlbench.plotting import plot_pareto, plot_redteam, plot_scores
from controlbench.tasks import get_task
import pytest


@pytest.fixture(scope="module")
def small_experiment(sandbox):
    cfg = ExperimentConfig(n_episodes=12, n_tasks=15, audit_budgets=(0.0, 0.1), defer_fractions=(0.0, 0.5, 1.0),
                           red_styles=("magic", "camouflage"), red_rates=(1.0,), red_selections=("random",))
    return run_experiment(cfg, sandbox)


def test_baselines_and_ordering(small_experiment):
    by = {(p["protocol"], tuple(sorted(p["params"].items()))): p for p in small_experiment.pareto}
    untrusted = by[("untrusted_only", ())]
    trusted = by[("trusted_only", ())]
    assert untrusted["usefulness"] == 1.0 and untrusted["worst_case_safety"] == 0.0
    assert trusted["worst_case_safety"] == 1.0 and trusted["usefulness"] < 0.9
    full_defer = by[("defer_to_trusted", (("audit_budget", 0.05), ("defer_fraction", 1.0)))]
    assert full_defer["worst_case_safety"] == 1.0
    assert full_defer["usefulness"] == pytest.approx(trusted["usefulness"], abs=0.1)
    no_audit = by[("trusted_monitoring", (("audit_budget", 0.0),))]
    audited = by[("trusted_monitoring", (("audit_budget", 0.1),))]
    assert audited["worst_case_safety"] >= no_audit["worst_case_safety"]


def test_frontier_is_non_dominated(small_experiment):
    table = small_experiment.pareto
    front = [p for p in table if p["on_frontier"]]
    assert front
    for p in front:
        assert not any(q["usefulness"] >= p["usefulness"] and q["worst_case_safety"] > p["worst_case_safety"]
                       for q in table)


def test_outputs_written(small_experiment, tmp_path):
    results, pareto = write_csvs(small_experiment, tmp_path)
    rows = list(csv.DictReader(results.open()))
    assert rows and {"protocol", "safety", "usefulness", "red_style"} <= set(rows[0])
    assert all(0 <= float(r["safety"]) <= 1 for r in rows)
    prow = list(csv.DictReader(pareto.open()))
    assert len(prow) == len(small_experiment.pareto)
    for fn, args in ((plot_pareto, (small_experiment.pareto,)), (plot_redteam, (small_experiment.rows,))):
        p = fn(*args, tmp_path / f"{fn.__name__}.png")
        assert p.stat().st_size > 5000
    assert plot_scores(small_experiment.honest_scores, small_experiment.attack_scores,
                       tmp_path / "s.png").exists()


def test_experiment_is_reproducible(sandbox):
    cfg = ExperimentConfig(n_episodes=5, n_tasks=8, audit_budgets=(0.1,), defer_fractions=(0.5,),
                           red_styles=("subtle",), red_rates=(1.0,), red_selections=("random",), seed=5)
    a = run_experiment(cfg, sandbox).pareto
    b = run_experiment(cfg, sandbox).pareto
    assert a == b


# ------------------------------------------------------------ claude adapter
class _Block:
    def __init__(self, text):
        self.text = text


class _Resp:
    def __init__(self, text):
        self.content = [_Block(text)]


class FakeClient:
    def __init__(self, reply):
        self.reply, self.calls = reply, []
        self.messages = self

    def create(self, **kw):
        self.calls.append(kw)
        return _Resp(self.reply)


def test_claude_adapter_is_off_by_default(monkeypatch):
    monkeypatch.delenv("CONTROLBENCH_ENABLE_CLAUDE", raising=False)
    with pytest.raises(ClaudeDisabled):
        ClaudeMonitor()
    monkeypatch.setenv("CONTROLBENCH_ENABLE_CLAUDE", "1")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ClaudeDisabled):
        ClaudeUntrusted()


def test_claude_adapter_with_injected_client():
    t = get_task("fib")
    client = FakeClient("```python\ndef fib(n):\n    return n\n```")
    pol = ClaudeUntrusted(attack=True, client=client)
    c = pol.generate(t, 0)
    assert c.code.startswith("def fib") and c.is_attack
    pol.generate(t, 0)
    assert len(client.calls) == 1  # memoised
    assert ClaudeMonitor(client=FakeClient("Suspicion: 7.5")).score(t, "x") == 7.5
    assert ClaudeMonitor(client=FakeClient("no idea")).score(t, "x") == 5.0
    assert extract_code("plain") == "plain\n"
