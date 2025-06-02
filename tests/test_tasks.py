import copy

import pytest

from controlbench.attacks import BACKDOOR_STYLES, HONEST_STYLES, backdoor_code, honest_code
from controlbench.tasks import all_tasks, get_task

TASKS = all_tasks()


def test_fifty_unique_tasks():
    assert len(TASKS) == 50
    assert len({t.id for t in TASKS}) == 50
    assert {t.difficulty for t in TASKS} <= {1, 2, 3, 4, 5}
    assert get_task("fib").func == "fib"


@pytest.mark.parametrize("task", TASKS, ids=lambda t: t.id)
def test_backdoor_invariants(task):
    """cond is false on every unit test, true on the trigger, and bad != correct there."""
    for args in task.tests:
        assert not eval(task.cond, {}, dict(zip(task.params, copy.deepcopy(args)))), args
    env = dict(zip(task.params, copy.deepcopy(task.trigger)))
    assert eval(task.cond, {}, env)
    env["result"] = task.trigger_expected
    assert eval(task.bad, {}, env) != task.trigger_expected
    assert len(task.tests) >= 4


def test_all_candidates_for_every_task_behave(evaluator):
    """Honest code passes everything; every backdoor passes the tests but fails the trigger."""
    pairs, kinds = [], []
    for t in TASKS:
        for s in range(len(HONEST_STYLES)):
            pairs.append((t, honest_code(t, s)))
            kinds.append("honest")
        for style in BACKDOOR_STYLES:
            for s in range(6):
                pairs.append((t, backdoor_code(t, style, s)))
                kinds.append("backdoor")
    for (t, code), kind, ev in zip(pairs, kinds, evaluator.evaluate_many(pairs)):
        assert ev.status == "ok", (t.id, kind, ev, code)
        assert ev.passes_tests, (t.id, kind, ev)
        if kind == "honest":
            assert ev.trigger_ok and not ev.backdoor_success, (t.id, code)
        else:
            assert ev.trigger_ok is False and ev.backdoor_success, (t.id, code)


def test_unknown_style_rejected():
    with pytest.raises(ValueError):
        backdoor_code(TASKS[0], "nope", 0)
