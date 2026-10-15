"""Actual retained CLI inputs/files with explicit subprocess/startup seams.

These prove adapter/CLI contracts, not installed SDK or real UID handoff.
"""

import io
import json
import os
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl import (
    being_seed,
    onboarding_source as source_cli,
    onboarding_receiving_update as receiving,
)
from clusterctl.onboarding import OnboardingError, digest


@pytest.fixture
def adapter(tmp_path, monkeypatch):
    config = tmp_path / "source.json"
    being_seed._write(config, {"synthetic": "configuration"})
    root = tmp_path / "owner-runtime"
    socket = tmp_path / "owner-output/tribe.sock"
    private = tmp_path / "private-sdk"
    origin = {"embodiment_id": "body:fixture", "incarnation_id": "incarnation:fixture"}
    result = dict(
        process={"pid": 123},
        server=origin,
        group={"socket": str(socket)},
        gate={"controlled": True, "process_id": 123},
        runtime_status={
            "local_origin": origin,
            "loaded_runtime": {"process_id": 123},
            "loaded_application": {"view": "fixture"},
        },
    )
    calls = []

    def run(argv, **options):
        calls.append((argv, options))
        return SimpleNamespace(returncode=0, stdout=json.dumps(result))

    uid, gid = os.geteuid(), os.getegid()
    monkeypatch.setattr(
        receiving, "os", SimpleNamespace(geteuid=lambda: 0, defpath=os.defpath)
    )
    monkeypatch.setattr(receiving.subprocess, "run", run)
    read = Path.read_bytes

    def protected(path):
        if path == private or private in path.parents or path == config:
            pytest.fail("root adapter read private SDK/config content")
        return read(path)

    monkeypatch.setattr(Path, "read_bytes", protected)
    client = receiving.SourceGroupClient(
        config=config,
        config_sha256=digest({"synthetic": "configuration"}),
        owner_uid=uid,
        owner_gid=gid,
        code=tmp_path / "public",
        code_digest="a" * 64,
        code_uid=0,
        venv=private / "venv",
        imports=private / "runtime-imports",
        root=root,
        socket_path=socket,
    )
    return client, result, calls


def test_source_owner_adapter_uses_closed_command_and_drops_privileges_before_exec(
    adapter,
):
    client, result, calls = adapter
    assert client.status() == result
    argv, options = calls[0]
    assert argv[:5] == [str(client.venv / "bin/python"), "-B", "-I", "-S", "-c"]
    assert "clusterctl.onboarding_source" in argv and "--owner-status" in argv
    assert options["user"] == client.owner_uid and options["group"] == client.owner_gid
    assert options["extra_groups"] == () and "preexec_fn" not in options
    assert "--expected-config-sha256" in argv and "--observation-deadline-ns" in argv
    assert 0 < options["timeout"] <= 30


def test_owner_private_control_paths_and_public_stdin_stay_in_owner_cli(adapter):
    client, _, calls = adapter
    path = client.root / "receiving-control/request.json"
    command = {"phase": "revoke", "readers": []}
    client.prepare_control(command, path)
    client.apply_control(path)
    assert json.loads(calls[0][1]["input"]) == command
    assert calls[0][0][-4:] == [
        "--prepare-control",
        str(path),
        "--control-command",
        "-",
    ]
    assert (
        calls[1][0][-2:] == ["--apply-control", str(path)]
        and calls[1][1]["input"] is None
    )


@pytest.mark.parametrize('publication', [False, True])
def test_group_relationship_uses_qualified_owner_and_only_public_stdin(adapter, publication):
    client, _, calls = adapter
    command = dict(operation_id=str(uuid.uuid4()), step='invite', method='tribe.invite', params={'payload': {}})
    if publication:
        command = dict(operation_id=str(uuid.uuid4()), step='select', action='selection',
                       params=dict(expected_selection_sha256=None))
        client.group_publication(command, authority_closure={})
    else:
        client.group_relationship(command, offline=True, authority_closure={})
    argv, options = calls[0]
    assert argv[-2:] == ['--group-request', '-']
    assert options['user'] == client.owner_uid and options['extra_groups'] == ()
    assert json.loads(options['input']) == dict(command=command, offline=True, authority_closure={})
    assert '--observation-deadline-ns' in argv and command['operation_id'] not in argv


def test_source_lifecycle_is_read_as_owner_and_never_falls_back_to_root(adapter):
    client, result, calls = adapter
    with pytest.raises(OnboardingError, match='lifecycle_binding_required'):
        client.lifecycle_operation('fixture-operation')
    assert calls == []
    client.lifecycle_journal = client.root / 'update-journal'
    result.clear()
    row = dict(operation_id='fixture-operation', operation='receiving-update')
    result.update(schema='cluster-receiving-source-lifecycle/v1',
        source_config_sha256=client.config_sha256, lifecycle=row)
    assert client.lifecycle_operation('fixture-operation') == row
    argv, options = calls[-1]
    assert argv[-4:] == ['--receiving-lifecycle', 'fixture-operation',
        '--operation-journal', str(client.lifecycle_journal)]
    assert options['user'] == client.owner_uid and options['extra_groups'] == ()
    row['operation_id'] = 'another-operation'
    with pytest.raises(OnboardingError, match='lifecycle_conflict'):
        client.lifecycle_operation('fixture-operation')


@pytest.mark.parametrize("part", ["group", "process", "origin", "loaded"])
def test_malformed_owner_observation_cannot_be_cohort_readiness(adapter, part):
    client, result, _ = adapter
    if part == "group":
        result["group"] = None
    elif part == "process":
        result["process"] = None
    elif part == "origin":
        result["server"] = {}
    else:
        result["runtime_status"]["loaded_runtime"]["process_id"] = 456
    with pytest.raises(OnboardingError, match="observation_conflict"):
        client.status()


def test_late_owner_reply_is_uncertain_and_keeps_exact_public_command(
    adapter, monkeypatch
):
    client, _, calls = adapter
    clock = [100]
    monkeypatch.setattr(receiving.time, "monotonic_ns", lambda: clock[0])
    client.deadline_ns = 1000
    run = receiving.subprocess.run

    def late(*arguments, **options):
        result = run(*arguments, **options)
        clock[0] = 1001
        return result

    monkeypatch.setattr(receiving.subprocess, "run", late)
    command = {"phase": "revoke", "readers": []}
    with pytest.raises(OnboardingError, match="deadline_expired"):
        client.prepare_control(command, client.root / "request.json")
    assert json.loads(calls[0][1]["input"]) == command
    assert client.deadline_ns == 1000


def test_final_config_check_cannot_refund_owner_deadline(adapter, monkeypatch):
    client, _, calls = adapter
    clock = [100]
    monkeypatch.setattr(receiving.time, "monotonic_ns", lambda: clock[0])
    client.deadline_ns = 1000
    actual = Path.lstat
    reads = []

    def late(path):
        result = actual(path)
        if path == client.config:
            reads.append(True)
            if len(reads) == 2:
                clock[0] = 1001
        return result

    monkeypatch.setattr(Path, "lstat", late)
    with pytest.raises(OnboardingError, match="deadline_expired"):
        client.status()
    assert len(calls) == 1 and len(reads) == 2


@pytest.fixture
def cli(tmp_path, monkeypatch):
    config = tmp_path / "source.json"
    settings = {"synthetic": "configuration"}
    being_seed._write(config, settings)
    calls = []

    class Source:
        def __init__(self, *args, **options):
            calls.append(("construct", args, options))

        def receiving_control(self, *args, **options):
            calls.append(("control", args, options))
            return {"retained": True}

        def receiving_observation(self, **options):
            calls.append(("observe", options))
            return {"identity": "fixture"}

        def receiving_lifecycle(self, *args):
            calls.append(('lifecycle', args))
            return {'retained': True}

        def group_relationship(self, *args, **options):
            calls.append(('group', args, options))
            return {'schema': 'cluster-group-relationship-result/v1', 'status': 'recorded'}

        def group_publication(self, *args, **options):
            calls.append(('group-publication', args, options))
            return {'schema': 'cluster-group-publication-result/v1', 'status': 'recorded'}

        def serve(self, *args, **options):
            pytest.fail("receiving mode started a service")

    monkeypatch.setattr(source_cli, "Source", Source)
    from clusterctl import onboarding_code_successor, onboarding_sdk

    monkeypatch.setattr(
        onboarding_code_successor,
        "sdk_parameters",
        lambda *_args, **_options: {"matrix_commit": "a" * 40},
    )
    monkeypatch.setattr(
        onboarding_sdk,
        "qualified_startup",
        lambda *_args, **_options: {"synthetic": "startup-seam"},
    )
    arguments = [
        "--config",
        str(config),
        "--code-owner",
        str(os.geteuid()),
        "--code-digest",
        "b" * 64,
        "--expected-config-sha256",
        digest(settings),
        "--observation-deadline-ns",
        str(time.monotonic_ns() + 30_000_000_000),
    ]
    return arguments, calls


@pytest.mark.parametrize('publication', [False, True])
def test_source_cli_group_request_keeps_finite_owner_context_and_never_serves(cli, monkeypatch, capsys, publication):
    arguments, calls = cli
    command = dict(operation_id=str(uuid.uuid4()), step='invite', method='tribe.invite', params={'payload': {}})
    if publication:
        command = dict(operation_id=str(uuid.uuid4()), step='select', action='selection',
                       params=dict(expected_selection_sha256=None))
    packet = dict(command=command, offline=True, authority_closure={})
    monkeypatch.setattr(source_cli.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(packet).encode())))
    assert source_cli.main([*arguments, '--group-request', '-']) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'recorded'
    assert [row[0] for row in calls] == ['construct', 'group-publication' if publication else 'group']
    assert calls[1][1] == (command,)
    if not publication:
        assert calls[1][2]['offline'] is True
    assert calls[1][2]['authority_closure'] == {}
    assert calls[1][2]['deadline_ns'] == int(arguments[-1])


@pytest.mark.parametrize('verb,action', [('--prepare-control', 'receiving-control-prepare'),
    ('--prepare-apply-control', 'receiving-control-prepare-apply')])
def test_source_cli_stdin_control_preserves_one_original_deadline(
    cli, monkeypatch, capsys, verb, action
):
    args, calls = cli
    command = {"phase": "revoke", "readers": []}
    monkeypatch.setattr(
        source_cli.sys,
        "stdin",
        SimpleNamespace(buffer=io.BytesIO(json.dumps(command).encode())),
    )
    assert (
        source_cli.main(
            [
                *args,
                verb,
                "/owner/control.json",
                "--control-command",
                "-",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {"retained": True}
    assert calls[-1][1] == (action, Path("/owner/control.json"))
    assert calls[-1][2]["command"] == command
    assert calls[-1][2]["deadline_ns"] == int(args[-1])


@pytest.mark.parametrize(
    "payload", [b"[]", b"{invalid", b"x" * (being_seed.MAX_SELECTION + 1)]
)
def test_source_cli_malformed_stdin_refuses_before_owner_state(
    cli, monkeypatch, capsys, payload
):
    args, calls = cli
    monkeypatch.setattr(
        source_cli.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload))
    )
    assert (
        source_cli.main(
            [
                *args,
                "--prepare-control",
                "/owner/control.json",
                "--control-command",
                "-",
            ]
        )
        == 1
    )
    assert (
        calls == []
        and json.loads(capsys.readouterr().out)["error"]
        == "native_onboarding_source_refused"
    )


def test_expired_source_deadline_refuses_before_qualified_startup_and_config(
    cli, monkeypatch, capsys
):
    args, calls = cli
    args[-1] = "1"
    from clusterctl import onboarding_sdk

    monkeypatch.setattr(
        onboarding_sdk,
        "qualified_startup",
        lambda *_args, **_options: pytest.fail("expired startup ran"),
    )
    assert source_cli.main([*args, "--owner-status"]) == 1
    assert (
        calls == []
        and json.loads(capsys.readouterr().out)["error"]
        == "native_onboarding_source_refused"
    )


def test_source_identity_mode_uses_no_guest_admission(cli, capsys):
    args, calls = cli
    until = time.time_ns() // 1_000_000 + 300000
    assert (
        source_cli.main(
            [*args, "--qualified-identity", "--identity-expires-at-ms", str(until)]
        )
        == 0
    )
    assert calls[-1] == (
        "observe",
        {"expires_at_ms": until, "deadline_ns": int(args[-1])},
    )
    assert json.loads(capsys.readouterr().out) == {"identity": "fixture"}


def test_source_lifecycle_cli_queries_without_serving_or_native_observation(cli, capsys):
    args, calls = cli
    assert source_cli.main([*args, '--receiving-lifecycle', 'operation',
        '--operation-journal', '/owner/journal']) == 0
    assert calls[-1] == ('lifecycle', (Path('/owner/journal'), 'operation'))
    assert not any(call[0] in {'control', 'observe'} for call in calls)
    assert json.loads(capsys.readouterr().out) == {'retained': True}


@pytest.mark.parametrize('extra', [[], ['--owner-status'], ['--require-loaded']])
def test_lifecycle_cli_requires_exact_query_mode(cli, capsys, extra):
    args, calls = cli
    flags = ['--receiving-lifecycle', 'operation', *extra]
    if extra:
        flags.extend(['--operation-journal', '/owner/journal'])
    assert source_cli.main([*args, *flags]) == 1
    assert calls == []
    assert json.loads(capsys.readouterr().out)['error'] == 'native_onboarding_source_refused'


def test_source_lifecycle_projection_binds_config_and_omits_unrelated_journal_data(tmp_path):
    from clusterctl.onboarding_code_successor import plan_update
    from clusterctl.operation_journal import OperationJournal
    root = tmp_path / 'runtime'
    root.mkdir(mode=0o700)
    settings = dict(schema='cluster-onboarding-source/v1', runtime_root=str(root),
        password_file=str(tmp_path / 'unused.unlock'), native_visibility=str(tmp_path / 'unused.json'),
        outputs=str(tmp_path / 'outputs'), applications=[])
    config = tmp_path / 'source.json'
    being_seed._write(config, settings)
    source = source_cli.Source(settings)
    journal_path = tmp_path / 'owner-journal'
    journal = OperationJournal(journal_path)
    row = plan_update(journal, manifest_digest='a' * 64, target='receiving:source',
        expected_precondition={'source_bootstrap': {'settings_sha256': digest(settings),
            'predecessor': {'process': {'pid': 42}}, 'private_metadata': 'not-exported'}},
        intended_transition={'source_bootstrap': {'transaction': '/owner/private-transaction',
            'qualification': {'code': '/public/code', 'code_uid': 0, 'config': str(config)}}},
        audit_identity={'actor': 'synthetic-private-audit'})
    effects = {'quiesced': {'exit_observed': True}, 'controlled_loaded': {'process': {'pid': 43}},
        'unrelated_private_metadata': 'not-exported'}
    journal.advance(row['operation_id'], 'runtime-dispatching',
        runtime_observation={'source_bootstrap': effects})
    before = journal.get(row['operation_id'])
    projection = source.receiving_lifecycle(journal_path, row['operation_id'])
    exported = projection['lifecycle']
    assert projection['source_config_sha256'] == digest(settings)
    assert set(exported['runtime_observation']['source_bootstrap']) == {'quiesced', 'controlled_loaded'}
    assert 'not-exported' not in json.dumps(projection)
    assert 'synthetic-private-audit' not in json.dumps(projection)
    assert journal.get(row['operation_id']) == before
    source.settings = {**settings, 'applications': ['another-source']}
    with pytest.raises(OnboardingError, match='lifecycle_conflict'):
        source.receiving_lifecycle(journal_path, row['operation_id'])
