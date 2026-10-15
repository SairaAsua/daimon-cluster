"""Bounded host worker; no HTTP privilege, model turns or Matrix inbox attention.

A backend reconciles only explicitly authorized onboarding jobs. A slow job has
its own slot and lock; HTTP request lifetime and stdout capture are irrelevant.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import signal
import threading
import time
from pathlib import Path
from typing import Callable

from . import being_seed
from .onboarding import Backend, JobStore, OnboardingError


class Worker:
    def __init__(self, store: JobStore, backend: Callable[[], Backend], *, concurrency: int = 2,
                 publish: Callable[[dict], None] | None = None,
                 plans: Callable[[], list[dict]] | None = None,
                 homes: Callable[[dict], dict] | None = None,
                 advance_group_admission: Callable[[str], object] | None = None):
        if type(concurrency) is not int or not 1 <= concurrency <= 8:
            raise OnboardingError("invalid_worker_concurrency")
        self.store, self.backend = store, backend
        self.concurrency = concurrency
        self.publish = publish
        self.plans = plans
        self.homes = homes
        self.advance_group_admission = advance_group_admission

    def _enqueue(self) -> None:
        if self.plans:
            for plan in self.plans():
                try:
                    self.store.submit(plan, self.backend)
                except (OnboardingError, being_seed.SeedError, OSError, ValueError):
                    continue

    def _tick(self, name: str) -> dict:
        try:
            reconcile = getattr(self.homes, 'reconcile_committed', None)
            if reconcile:
                reconcile(name)
            if self.advance_group_admission:
                self.advance_group_admission(name)
            # Resolve again inside the job lock: a concurrent receiving
            # selection can change runtime pins while the coordinator runs.
            result = self.store.tick(name, self.backend)
            if self.publish:
                self.publish(result)
            if self.homes:
                self.homes(result)
            return result
        except (OnboardingError, being_seed.SeedError, OSError, ValueError, TypeError, KeyError):
            # Do not print name/content/exception from an invalid private record.
            return {"state": "attention-required", "reason": "verification_failed"}
        except Exception:
            return {"state": "attention-required", "reason": "backend_unavailable"}

    def once(self) -> list[dict]:
        self._enqueue()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            return list(pool.map(self._tick, self.store.names()))

    def run(self, stop: threading.Event, *, interval: float = 5) -> None:
        if not 0.1 <= interval <= 60:
            raise OnboardingError("invalid_worker_interval")
        # A running job is never submitted twice by this process. Completed
        # slots are replenished immediately, even if another job remains slow.
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            pending: dict[str, concurrent.futures.Future] = {}
            scheduled: dict[str, float] = {}
            while not stop.is_set():
                self._enqueue()
                for name in list(pending):
                    if pending[name].done():
                        pending.pop(name).result()
                for name in sorted(self.store.names(), key=lambda name: scheduled.get(name, 0)):
                    if len(pending) >= self.concurrency:
                        break
                    if name not in pending:
                        pending[name] = pool.submit(self._tick, name)
                        scheduled[name] = time.monotonic()
                stop.wait(interval)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument('--home-placements',type=Path)
    args = parser.parse_args(argv)
    try:
        from .onboarding_host import HostBackend, CurrentHostConfig

        selections = CurrentHostConfig(args.config)
        config = selections.current()
        from .onboarding_input import VerificationCache
        inputs = VerificationCache()
        def backend():
            return HostBackend(selections.current(), input_cache=inputs)
        from .onboarding_progress import Progress

        progress = Progress(config.progress, worker_uid=os.geteuid()) if config.progress else None
        store=JobStore(config.jobs)
        homes=None
        if args.home_placements:
            if progress is None:
                raise OnboardingError('trusted_home_progress_required')
            from .onboarding_homes import configure
            homes=configure(args.home_placements,progress=config.progress,store=store,
                            backend=backend,worker_uid=os.geteuid())
        worker = Worker(store, backend, concurrency=config.concurrency,
                        publish=progress.publish if progress else None,
                        plans=lambda: selections.current().approved_plans(), homes=homes,
                        advance_group_admission=(lambda name: backend().advance_group_admission(name))
                            if config.group_admission is not None else None)
        if args.once:
            print(json.dumps(worker.once()))
            return 0
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        worker.run(stop)
        return 0
    except Exception:
        print(json.dumps({"error": "onboarding_worker_configuration_refused"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
