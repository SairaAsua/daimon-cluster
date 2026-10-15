"""Root-effect orchestration seams with real immutable files/unit CAS.

Manager, cgroup and process effects are explicit fakes. These do not qualify
an actual root guest/systemd/SDK deployment or receiving readiness.
"""

import copy
import hashlib
import os
import time
import uuid
from pathlib import Path

import pytest

from clusterctl import onboarding_service, owner_process
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_service import GuestServiceBootstrap, UNIT


def deadline():
    return time.monotonic_ns() + 2_000_000_000


def test_changed_frozen_dropin_bytes_prevent_first_stop(fixture):
    controller, manager, request = fixture[:3]
    request['predecessor']['service']['manager']['DropInPaths'] = '/maintained.conf'
    request['predecessor']['service']['dropins'] = {'/maintained.conf': 'a' * 64}
    manager._guest_dropins = lambda _: {'/maintained.conf': 'b' * 64}
    with pytest.raises(OnboardingError, match='request_conflict'):
        controller.execute('quiesce', request, deadline_ns=deadline())
    assert manager.stops == 0


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    unit = tmp_path / UNIT
    unit.write_bytes(
        b"[Service]\nUser=agent\nGroup=agent\nKillMode=control-group\nExecStart=/old\n"
    )
    unit.chmod(0o644)
    process = dict(pid=123, uid=1000, start_ticks=4, boot_id=str(uuid.uuid4()))
    parent = {**process, "pid": 122, "start_ticks": 3}

    class Manager:
        _unit_uid = os.geteuid()

        def __init__(self):
            self.unit = unit
            self.state = "active"
            self.invocation = "original-invocation"
            self.stops = self.starts = 0
            self.exited = {123: False, 122: False}
            self.lose = None
            self.dropins = {}
            self.reload_dropins = None

        def inspect(self, **_):
            running = self.state in {"active", "activating", "deactivating"}
            result = dict(
                unit_sha256=hashlib.sha256(unit.read_bytes()).hexdigest(),
                manager=dict(
                    ActiveState=self.state,
                    SubState="running" if running else "dead",
                    MainPID=("222" if self.starts else "122") if running else "0",
                    ControlGroup="/system.slice/" + UNIT,
                    InvocationID=self.invocation,
                    Result="success",
                    User="agent",
                    Group="agent",
                ),
            )
            if self.dropins:
                result['dropins'] = dict(self.dropins)
            return result

        def bind_admitted_process(self, observed, inspected):
            return dict(
                process=observed["process"],
                admission_parent=observed["admission_parent"],
                control_group=inspected["manager"]["ControlGroup"],
                invocation_id=self.invocation,
            )

        def stop(self, **_):
            self.stops += 1
            self.state = "inactive"
            self.exited = {123: True, 122: True}
            if self.lose == "stop":
                raise OSError("synthetic lost stop return")

        def start(self, **options):
            if self.reload_dropins is not None:
                self.dropins = self.reload_dropins
            if 'pre_start' in options:
                options['pre_start']()
            self.starts += 1
            self.state = "active"
            self.invocation = "candidate-invocation"
            if self.lose == "start":
                raise OSError("synthetic lost start return")

    manager = Manager()
    previous = dict(service=manager.inspect(), process=process, admission_parent=parent)
    previous["scope"] = manager.bind_admitted_process(previous, previous["service"])
    request = dict(
        schema="cluster-guest-service-bootstrap/v1",
        operation_id=str(uuid.uuid4()),
        plan_digest="a" * 64,
        predecessor=previous,
        argv=["/qualified/owner-loader", "-I", "-S"],
    )

    class Pin:
        def __init__(self, process):
            self.process = process

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def wait_for_exit(self, _):
            return manager.exited[self.process["pid"]]

    monkeypatch.setattr(owner_process, "ProcessPresence", Pin)
    monkeypatch.setattr(
        owner_process,
        "observe_process_exit",
        lambda process: manager.exited[process["pid"]],
    )
    monkeypatch.setattr(
        GuestServiceBootstrap,
        "_parent",
        staticmethod(lambda _values: {**parent, "pid": 222, "start_ticks": 9}),
    )
    return GuestServiceBootstrap(manager), manager, request


@pytest.fixture
def initial(fixture):
    controller, manager, request = fixture
    manager.unit.unlink()
    manager.state = 'inactive'
    manager.invocation = ''
    manager.loaded = False
    manager.enables = 0
    inspect = manager.inspect
    def inspect_loaded(**options):
        if not manager.loaded:
            raise OnboardingError('receiving_matrix_service_scope_required')
        return inspect(**options)
    manager.inspect = inspect_loaded
    def initial_state(**_):
        return dict(unit_sha256=(hashlib.sha256(manager.unit.read_bytes()).hexdigest()
                                if manager.unit.exists() else None),
                    service=manager.inspect() if manager.loaded else None)
    def enable(**_):
        manager.enables += 1
    start = manager.start
    def start_loaded(**options):
        manager.loaded = True  # The actual start reloads before its callback.
        return start(**options)
    manager.initial_state = initial_state
    manager.enable = enable
    manager.start = start_loaded
    return controller, manager, {**request, 'schema': 'cluster-guest-service-initial/v1', 'predecessor': None}


def test_initial_service_recovers_lost_start_reply_without_fake_exit_or_second_start(initial):
    controller, manager, request = initial
    prepared = controller.execute('validate', request, deadline_ns=deadline())
    assert prepared['dispatch_state'] == 'not-dispatched'
    assert prepared['initial_service'] == dict(unit_sha256=None, service=None)
    controller.execute('select', request, deadline_ns=deadline())
    assert manager.enables == 1 and manager.starts == manager.stops == 0
    manager.lose = 'start'
    with pytest.raises(OSError, match='lost start'):
        controller.execute('start', request, deadline_ns=deadline())
    result = controller.execute('start', request, deadline_ns=deadline())
    assert result['schema'] == 'cluster-guest-service-initial-start/v1'
    assert result['initial_service'] == prepared['initial_service']
    assert not {'exits', 'exit_observed', 'quiesced', 'predecessor'} & set(result)
    assert result['admission_parent']['pid'] == 222
    observed = controller.execute('validate', request, deadline_ns=deadline())
    assert observed == {**prepared, 'dispatch_state': 'started-recorded'}
    controller.execute('select', request, deadline_ns=deadline())
    assert controller.execute('start', request, deadline_ns=deadline()) == result
    assert manager.enables == manager.starts == 1 and manager.stops == 0
    records = list(manager.unit.parent.glob('.*.selection/operations/*/*.json'))
    assert not any(path.stem in {'quiesced', 'process-exited', 'admission_parent-exited'} for path in records)


def test_initial_root_rechecks_fixed_expiry_after_guest_startup_work(initial, monkeypatch):
    controller, manager, request = initial
    wall = [time.time_ns()]
    request = {**request, 'not_after_ms': wall[0] // 1_000_000 + 60000}
    controller.execute('validate', request, deadline_ns=deadline())
    controller.execute('select', request, deadline_ns=deadline())
    start = manager.start
    def delayed(**options):
        wall[0] = request['not_after_ms'] * 1_000_000
        return start(**options)
    manager.start = delayed
    monkeypatch.setattr(onboarding_service.time, 'time_ns', lambda: wall[0])
    with pytest.raises(OnboardingError, match='authorization_expired'):
        controller.execute('start', request, deadline_ns=deadline())
    assert manager.starts == 0


def test_initial_root_expiry_does_not_replay_or_hide_recorded_start(initial, monkeypatch):
    controller, manager, request = initial
    request = {**request, 'not_after_ms': time.time_ns() // 1_000_000 + 60000}
    controller.execute('validate', request, deadline_ns=deadline())
    selected = controller.execute('select', request, deadline_ns=deadline())
    started = controller.execute('start', request, deadline_ns=deadline())
    monkeypatch.setattr(onboarding_service.time, 'time_ns', lambda: (request['not_after_ms'] + 1) * 1_000_000)
    assert controller.execute('select', request, deadline_ns=deadline()) == selected
    assert controller.execute('start', request, deadline_ns=deadline()) == started
    assert manager.starts == manager.enables == 1


def test_initial_root_refuses_expired_first_selection_without_publishing(initial, monkeypatch):
    controller, manager, request = initial
    request = {**request, 'not_after_ms': time.time_ns() // 1_000_000 + 60000}
    controller.execute('validate', request, deadline_ns=deadline())
    monkeypatch.setattr(onboarding_service.time, 'time_ns', lambda: request['not_after_ms'] * 1_000_000)
    with pytest.raises(OnboardingError, match='authorization_expired'):
        controller.execute('select', request, deadline_ns=deadline())
    assert not manager.unit.exists() and manager.starts == manager.enables == 0


@pytest.mark.parametrize('evidence', ['unseen-stopped', 'pending', 'started'])
def test_initial_start_never_replays_a_dead_or_replaced_invocation(initial, monkeypatch, evidence):
    controller, manager, request = initial
    controller.execute('validate', request, deadline_ns=deadline())
    controller.execute('select', request, deadline_ns=deadline())
    if evidence == 'unseen-stopped':
        manager.lose = 'start'
        with pytest.raises(OSError):
            controller.execute('start', request, deadline_ns=deadline())
        manager.state = 'inactive'
        manager.invocation = ''
        error = 'initial_start_uncertain'
    elif evidence == 'pending':
        def lost(_values):
            raise OSError('synthetic lost parent observation')
        monkeypatch.setattr(controller, '_parent', lost)
        with pytest.raises(OSError, match='parent observation'):
            controller.execute('start', request, deadline_ns=deadline())
        manager.invocation = 'replacement'
        error = 'started_process_changed'
    else:
        controller.execute('start', request, deadline_ns=deadline())
        manager.invocation = 'replacement'
        error = 'started_process_changed'
    with pytest.raises(OnboardingError, match=error):
        controller.execute('start', request, deadline_ns=deadline())
    assert manager.starts == manager.enables == 1 and manager.stops == 0


def test_initial_service_preserves_foreign_unit_and_rechecks_reload_before_dispatch(initial):
    controller, manager, request = initial
    foreign = b'[Service]\nUser=agent\nGroup=agent\nExecStart=/foreign\n'
    manager.unit.write_bytes(foreign)
    manager.unit.chmod(0o600)
    with pytest.raises(OnboardingError, match='candidate_changed'):
        controller.execute('validate', request, deadline_ns=deadline())
    assert manager.unit.read_bytes() == foreign and manager.starts == manager.enables == 0
    manager.unit.unlink()
    controller.execute('validate', request, deadline_ns=deadline())
    controller.execute('select', request, deadline_ns=deadline())
    candidate = manager.unit.read_bytes()
    start = manager.start
    def changed_reload(**options):
        manager.unit.write_bytes(foreign)
        return start(**options)
    manager.start = changed_reload
    with pytest.raises(OnboardingError, match='candidate_changed'):
        controller.execute('start', request, deadline_ns=deadline())
    assert manager.starts == manager.stops == 0
    manager.unit.write_bytes(candidate)
    manager.start = start
    controller.execute('start', request, deadline_ns=deadline())
    assert manager.starts == 1
    with pytest.raises(OnboardingError, match='request_required'):
        controller.execute('quiesce', request, deadline_ns=deadline())
    assert manager.stops == 0


def test_initial_start_requires_effective_unit_inspection_before_dispatch(initial):
    controller, manager, request = initial
    controller.execute('validate', request, deadline_ns=deadline())
    controller.execute('select', request, deadline_ns=deadline())
    # Model daemon-reload returning without an inspectable effective unit. The
    # absent view is valid before installation, never a start precondition.
    manager.start = lambda **options: type(manager).start(manager, **options)
    with pytest.raises(OnboardingError, match='service_scope_required'):
        controller.execute('start', request, deadline_ns=deadline())
    assert manager.starts == manager.stops == 0
    assert not list(manager.unit.parent.glob('.*.selection/operations/*/initial-start-intent.json'))


def test_initial_start_retains_allowed_dropins_across_lost_reply(initial):
    controller, manager, request = initial
    controller.execute('validate', request, deadline_ns=deadline())
    controller.execute('select', request, deadline_ns=deadline())
    # This path is a supported guest addition, so normal inspect() alone does
    # not reject its removal. Pin the exact effective vector before StartUnit.
    manager.reload_dropins = {'/run/systemd/system/service.d/zzz-lxc-service.conf': 'a' * 64}
    manager.lose = 'start'
    with pytest.raises(OSError, match='lost start'):
        controller.execute('start', request, deadline_ns=deadline())
    manager.dropins = {}
    with pytest.raises(OnboardingError, match='candidate_changed'):
        controller.execute('start', request, deadline_ns=deadline())
    assert manager.starts == manager.enables == 1 and manager.stops == 0
    assert manager.dropins == {}
    assert not list(manager.unit.parent.glob('.*.selection/operations/*/initial-started.json'))


def test_reload_exposes_changed_dropin_before_actual_start(fixture):
    controller, manager, request = fixture
    controller.execute('quiesce', request, deadline_ns=deadline())
    controller.execute('select', request, deadline_ns=deadline())
    manager.reload_dropins = {'/newly-loaded-override.conf': 'b' * 64}
    with pytest.raises(OnboardingError, match='quiescence_required'):
        controller.execute('start', request, deadline_ns=deadline())
    assert manager.starts == 0 and manager.state == 'inactive'


def test_reload_restores_original_unit_before_actual_start(fixture):
    controller, manager, request = fixture
    original = manager.unit.read_bytes()
    controller.execute('quiesce', request, deadline_ns=deadline())
    controller.execute('select', request, deadline_ns=deadline())
    actual = manager.start
    def start(**kwargs):
        manager.unit.write_bytes(original)
        actual(**kwargs)
    manager.start = start
    with pytest.raises(OnboardingError, match='candidate_changed'):
        controller.execute('start', request, deadline_ns=deadline())
    assert manager.starts == 0 and manager.state == 'inactive'


def test_type_simple_pending_owner_is_observed_without_second_start(fixture):
    controller, manager, request = fixture
    controller.execute('quiesce', request, deadline_ns=deadline())
    controller.execute('select', request, deadline_ns=deadline())
    original = controller._parent
    calls = []
    def parent(values):
        calls.append(values['MainPID'])
        if len(calls) == 1:
            raise owner_process.PresenceError('synthetic pending setuid')
        return original(values)
    controller._parent = parent
    started = controller.execute('start', request, deadline_ns=deadline())
    assert calls == ['222', '222'] and manager.starts == 1
    assert controller.execute('start', request, deadline_ns=deadline()) == started
    assert manager.starts == 1


def test_pending_owner_cannot_adopt_another_invocation(fixture):
    controller, manager, request = fixture
    controller.execute('quiesce', request, deadline_ns=deadline())
    controller.execute('select', request, deadline_ns=deadline())
    def parent(_):
        manager.invocation = 'independent replacement'
        raise owner_process.PresenceError('synthetic pending setuid')
    controller._parent = parent
    with pytest.raises(OnboardingError, match='started_process_changed'):
        controller.execute('start', request, deadline_ns=deadline())
    assert manager.starts == 1 and manager.stops == 1


@pytest.mark.parametrize('after_deadline', ['same', 'replacement', 'inactive'])
def test_pending_owner_deadline_retains_observation_for_exact_retry(fixture, after_deadline, monkeypatch):
    controller, manager, request = fixture
    controller.execute('quiesce', request, deadline_ns=deadline())
    controller.execute('select', request, deadline_ns=deadline())
    original = controller._parent
    expiry = deadline()
    clock = [time.monotonic_ns()]
    def parent(_):
        clock[0] = expiry + 1
        raise owner_process.PresenceError('synthetic pending setuid')
    controller._parent = parent
    # Advance only at the observed owner transition, after durable start intent
    # and pending association; filesystem scheduling is not the tested contract.
    with monkeypatch.context() as patch:
        patch.setattr(onboarding_service.time, 'monotonic_ns', lambda: clock[0])
        with pytest.raises(OnboardingError, match='deadline_expired'):
            controller.execute('start', request, deadline_ns=expiry)
    assert manager.starts == 1
    controller._parent = original
    if after_deadline == 'same':
        assert controller.execute('start', request, deadline_ns=deadline())['admission_parent']['pid'] == 222
    else:
        if after_deadline == 'replacement':
            manager.invocation = 'replacement after deadline'
        else:
            manager.state = 'inactive'
        with pytest.raises(OnboardingError, match='started_process_changed'):
            controller.execute('start', request, deadline_ns=deadline())
    assert manager.starts == 1


def test_start_result_cannot_adopt_dropin_that_appeared_after_start(fixture):
    controller, manager, request = fixture
    controller.execute('quiesce', request, deadline_ns=deadline())
    controller.execute('select', request, deadline_ns=deadline())
    actual = manager.start
    def start(**kwargs):
        actual(**kwargs)
        manager.dropins = {'/changed-after-start.conf': 'b' * 64}
    manager.start = start
    with pytest.raises(OnboardingError, match='candidate_changed'):
        controller.execute('start', request, deadline_ns=deadline())
    assert manager.starts == 1
    operations = manager.unit.parent / ('.' + UNIT + '.selection') / 'operations' / request['operation_id']
    assert not (operations / 'started.json').exists()


def root_for(manager, request):
    return (
        manager.unit.parent
        / ("." + UNIT + ".selection")
        / "operations"
        / request["operation_id"]
    )


def test_complete_root_effect_retry_preserves_unit_and_never_restarts_current(fixture):
    controller, manager, request = fixture
    original = manager.unit.read_bytes()
    stopped = controller.execute("quiesce", request, deadline_ns=deadline())
    assert (
        all(stopped["exits"].values()) and stopped["graceful_delivery"] == "unobserved"
    )
    assert controller.execute("quiesce", request, deadline_ns=deadline()) == stopped
    selected = controller.execute("select", request, deadline_ns=deadline())
    assert controller.execute("select", request, deadline_ns=deadline()) == selected
    assert manager.unit.read_bytes().startswith(
        b"[Service]\nUser=agent\nGroup=agent\nKillMode=control-group\n"
    )
    assert (
        manager.unit.with_name(
            UNIT + "." + hashlib.sha256(original).hexdigest() + ".previous"
        ).read_bytes()
        == original
    )
    started = controller.execute("start", request, deadline_ns=deadline())
    assert started["receiving_readiness"] == "unobserved"
    assert controller.execute("start", request, deadline_ns=deadline()) == started
    assert manager.stops == manager.starts == 1
    with pytest.raises(OnboardingError, match="quiescence_required"):
        controller.execute("quiesce", request, deadline_ns=deadline())


def test_lost_stop_reply_retains_exit_evidence_before_pid_reuse(fixture, monkeypatch):
    controller, manager, request = fixture
    manager.lose = "stop"
    with pytest.raises(OSError, match="lost stop"):
        controller.execute("quiesce", request, deadline_ns=deadline())
    root = root_for(manager, request)
    assert (root / "process-exited.json").exists() and (
        root / "admission_parent-exited.json"
    ).exists()
    monkeypatch.setattr(
        owner_process,
        "observe_process_exit",
        lambda *_: pytest.fail("durable historical exit was re-probed after PID reuse"),
    )
    assert all(
        controller.execute("quiesce", request, deadline_ns=deadline())["exits"].values()
    )
    assert manager.stops == 1


@pytest.mark.parametrize("stage", ["quiesce", "select", "start"])
def test_lost_effect_publication_reply_reuses_exact_files_and_operations(
    fixture, monkeypatch, stage
):
    controller, manager, request = fixture
    if stage != "quiesce":
        controller.execute("quiesce", request, deadline_ns=deadline())
    if stage == "start":
        controller.execute("select", request, deadline_ns=deadline())
    actual = GuestServiceBootstrap._record
    filenames = {
        "quiesce": "quiesced.json",
        "select": "selected.json",
        "start": "started.json",
    }
    failed = []

    def lost(path, *args, **kwargs):
        actual(path, *args, **kwargs)
        if path.name == filenames[stage] and not failed:
            failed.append(path)
            raise OSError("synthetic lost immutable publication return")

    monkeypatch.setattr(GuestServiceBootstrap, "_record", staticmethod(lost))
    with pytest.raises(OSError, match="lost immutable"):
        controller.execute(stage, request, deadline_ns=deadline())
    result = controller.execute(stage, request, deadline_ns=deadline())
    assert controller.execute(stage, request, deadline_ns=deadline()) == result
    assert manager.stops == 1 and manager.starts == (1 if stage == "start" else 0)


def test_lost_unit_cas_return_and_start_dispatch_are_observed_not_repeated(
    fixture, monkeypatch
):
    controller, manager, request = fixture
    controller.execute("quiesce", request, deadline_ns=deadline())
    actual = onboarding_service.select_entrypoint
    failed = []

    def lost(*args, **kwargs):
        result = actual(*args, **kwargs)
        if not failed:
            failed.append(True)
            raise OSError("synthetic lost unit CAS return")
        return result

    monkeypatch.setattr(onboarding_service, "select_entrypoint", lost)
    with pytest.raises(OSError):
        controller.execute("select", request, deadline_ns=deadline())
    assert controller.execute("select", request, deadline_ns=deadline())["selected"]
    manager.lose = "start"
    with pytest.raises(OSError):
        controller.execute("start", request, deadline_ns=deadline())
    assert (
        controller.execute("start", request, deadline_ns=deadline())["manager"][
            "ActiveState"
        ]
        == "active"
    )
    assert manager.starts == 1


def test_parent_exit_is_independent_and_durable_while_child_is_still_alive(
    fixture, monkeypatch
):
    controller, manager, request = fixture

    def partial(**_):
        manager.stops += 1
        manager.state = "inactive"
        manager.exited[122] = True

    manager.stop = partial
    with pytest.raises(OnboardingError, match="deadline_expired"):
        controller.execute(
            "quiesce", request, deadline_ns=time.monotonic_ns() + 30_000_000
        )
    root = root_for(manager, request)
    assert (root / "admission_parent-exited.json").exists() and not (
        root / "quiesced.json"
    ).exists()
    manager.exited[123] = True

    def later(process):
        assert process["pid"] == 123
        return True

    monkeypatch.setattr(owner_process, "observe_process_exit", later)
    assert all(
        controller.execute("quiesce", request, deadline_ns=deadline())["exits"].values()
    )
    assert manager.stops == 1


@pytest.mark.parametrize("change", ["invocation", "uid", "request", "unit"])
def test_changed_precondition_or_request_never_stops_a_different_component(
    fixture, change
):
    controller, manager, request = fixture
    if change == "invocation":
        manager.invocation = "intervening-manager"
    elif change == "uid":
        request["predecessor"]["process"]["uid"] = 0
    elif change == "unit":
        manager.unit.write_bytes(manager.unit.read_bytes() + b"Unexpected=yes\n")
    else:
        controller.execute("quiesce", request, deadline_ns=deadline())
        request = copy.deepcopy(request)
        request["argv"] = ["/different-candidate"]
    before = manager.stops
    with pytest.raises((OnboardingError, OSError)):
        controller.execute("quiesce", request, deadline_ns=deadline())
    assert manager.stops == before


def test_start_rejects_an_independent_activation_or_replaced_started_process(fixture):
    controller, manager, request = fixture
    controller.execute("quiesce", request, deadline_ns=deadline())
    controller.execute("select", request, deadline_ns=deadline())
    manager.state = "active"
    manager.invocation = "independent-restart"
    with pytest.raises(OnboardingError, match="started_process_changed"):
        controller.execute("start", request, deadline_ns=deadline())
    assert manager.starts == 0
    manager.state = "inactive"
    manager.invocation = "original-invocation"
    controller.execute("start", request, deadline_ns=deadline())
    manager.invocation = "another-restart"
    with pytest.raises(OnboardingError, match="started_process_changed"):
        controller.execute("start", request, deadline_ns=deadline())
    assert manager.starts == 1


def test_expired_budget_creates_no_effect_or_operation_state(fixture):
    controller, manager, request = fixture
    with pytest.raises(OnboardingError, match="deadline_expired"):
        controller.execute("quiesce", request, deadline_ns=time.monotonic_ns() - 1)
    assert (
        manager.stops == manager.starts == 0 and not root_for(manager, request).exists()
    )


@pytest.mark.parametrize(
    "action",
    ["bootstrap-inspect", "bootstrap-quiesce", "bootstrap-select", "bootstrap-start"],
)
def test_closed_root_cli_never_calls_install_or_owner_sdk(monkeypatch, capsys, action):
    import json
    from tests.test_onboarding import plan
    from clusterctl.onboarding import digest

    selected = plan()
    calls = []
    monkeypatch.setattr(onboarding_service.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        onboarding_service.onboarding_release,
        "regular",
        lambda *_args, **_kwargs: json.dumps(selected).encode(),
    )
    monkeypatch.setattr(
        onboarding_service.onboarding_code_successor,
        "selection",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        onboarding_service,
        "install",
        lambda *_args, **_kwargs: pytest.fail("bootstrap verb invoked install/enable"),
    )

    class Controller:
        def __init__(self, manager):
            assert manager.unit == Path("/etc/systemd/system") / UNIT
            assert manager._manager_prefix == ["systemctl"] and manager._unit_uid == 0

        def inspect(self, observed, **kwargs):
            calls.append(("inspect", observed, kwargs))
            return {"receiving_readiness": "unobserved"}

        def execute(self, verb, request, **kwargs):
            assert request["plan_digest"] == digest(selected)
            calls.append((verb, request, kwargs))
            return {"receiving_readiness": "unobserved"}

    monkeypatch.setattr(onboarding_service, "GuestServiceBootstrap", Controller)
    argv = [
        "--code",
        "/opt/daimon-onboarding/" + selected["release_digest"],
        "--plan",
        "/home/agent/.onboarding-input/plan.json",
        "--action",
        action,
    ]
    if action != "bootstrap-inspect":
        argv += [
            "--bootstrap-request-json",
            json.dumps({"plan_digest": digest(selected)}),
        ]
    assert onboarding_service.main(argv) == 0
    assert len(calls) == 1 and calls[0][0] == action.removeprefix("bootstrap-")
    assert calls[0][2]["deadline_ns"] > time.monotonic_ns()
    assert capsys.readouterr().out == '{"receiving_readiness": "unobserved"}\n'


@pytest.mark.parametrize(
    "change",
    [
        "disk-user",
        "disk-group",
        "disk-missing-user",
        "disk-duplicate-user",
        "disk-continuation",
        "disk-comment-separator",
        "manager-user",
    ],
)
def test_next_execution_identity_must_be_bound_on_disk_and_in_manager(fixture, change):
    controller, manager, request = fixture
    raw = manager.unit.read_bytes()
    if change == "disk-user":
        raw = raw.replace(b"User=agent", b"User=root")
    elif change == "disk-group":
        raw = raw.replace(b"Group=agent", b"Group=root")
    elif change == "disk-missing-user":
        raw = raw.replace(b"User=agent\n", b"")
    elif change == "disk-duplicate-user":
        raw = raw.replace(b"User=agent", b"User=agent\nUser=agent")
    elif change == "disk-continuation":
        raw = raw.replace(b"User=agent", b"User=agent\\")
    elif change == "disk-comment-separator":
        raw = raw.replace(b"User=agent", b"# note\vUser=agent")
    else:
        request["predecessor"]["service"]["manager"]["User"] = "root"
    manager.unit.write_bytes(raw)
    request["predecessor"]["service"]["unit_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(OnboardingError):
        controller.execute("quiesce", request, deadline_ns=deadline())
    assert manager.stops == manager.starts == 0


@pytest.mark.parametrize("stage", ["quiesce", "select", "start"])
def test_actual_effect_rename_before_return_keeps_one_link_and_reconciles(
    fixture, monkeypatch, stage
):
    controller, manager, request = fixture
    if stage != "quiesce":
        controller.execute("quiesce", request, deadline_ns=deadline())
    if stage == "start":
        controller.execute("select", request, deadline_ns=deadline())
    filenames = {
        "quiesce": "quiesced.json",
        "select": "selected.json",
        "start": "started.json",
    }
    actual = onboarding_service.os.rename
    failed = []

    def lost(source, destination):
        actual(source, destination)
        if destination.name == filenames[stage] and not failed:
            failed.append(destination)
            raise OSError("synthetic crash after actual rename")

    monkeypatch.setattr(onboarding_service.os, "rename", lost)
    with pytest.raises(OSError, match="actual rename"):
        controller.execute(stage, request, deadline_ns=deadline())
    assert failed[0].stat().st_nlink == 1
    result = controller.execute(stage, request, deadline_ns=deadline())
    assert controller.execute(stage, request, deadline_ns=deadline()) == result
    assert manager.stops == 1 and manager.starts == (1 if stage == "start" else 0)


@pytest.mark.parametrize("stage", ["quiesce", "select", "start"])
def test_late_durability_preserves_evidence_without_late_success(
    fixture, monkeypatch, stage
):
    controller, manager, request = fixture
    if stage != "quiesce":
        controller.execute("quiesce", request, deadline_ns=deadline())
    if stage == "start":
        controller.execute("select", request, deadline_ns=deadline())
    filenames = {
        "quiesce": "quiesced.json",
        "select": "selected.json",
        "start": "started.json",
    }
    clock = [0]
    limit = 1_000_000_000
    monkeypatch.setattr(onboarding_service.time, "monotonic_ns", lambda: clock[0])
    actual = GuestServiceBootstrap._record

    def late(path, value):
        result = actual(path, value)
        if path.name == filenames[stage]:
            clock[0] = limit
        return result

    monkeypatch.setattr(GuestServiceBootstrap, "_record", staticmethod(late))
    with pytest.raises(OnboardingError, match="deadline_expired"):
        controller.execute(stage, request, deadline_ns=limit)
    assert (root_for(manager, request) / filenames[stage]).exists()
    monkeypatch.setattr(GuestServiceBootstrap, "_record", staticmethod(actual))
    clock[0] = 0
    controller.execute(stage, request, deadline_ns=limit)
    assert manager.stops == 1 and manager.starts == (1 if stage == "start" else 0)


def test_root_validates_actual_candidate_before_any_lifecycle_effect(fixture):
    controller, manager, request = fixture
    original = manager.unit.read_bytes()
    result = controller.execute('validate', request, deadline_ns=deadline())
    assert result['receiving_readiness'] == 'unobserved'
    assert manager.unit.read_bytes() == original and manager.stops == manager.starts == 0
    assert not (root_for(manager, request) / 'quiesced.json').exists()
    manager.invocation = 'different-invocation'
    with pytest.raises(OnboardingError, match='predecessor_changed'):
        controller.execute('validate', request, deadline_ns=deadline())
    assert manager.stops == manager.starts == 0
