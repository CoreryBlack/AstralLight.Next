"""Bounded, ordered execution of independent offline model configurations."""
from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
import importlib
import multiprocessing

MODEL_MODULES = {"e5_model_check", "e5_model_check_two_mutations"}
MAX_WORKERS = 12


def validate_workers(workers):
    if type(workers) is not int or not 1 <= workers <= MAX_WORKERS:
        raise ValueError("model workers must be an integer between 1 and 4")
    return workers


def configuration_key(model, premises, mode, bound):
    return (tuple(sorted(premises.items())), mode,
            "complete" if bound >= model.required_bound(premises, mode) else bound)


def _run_configuration(task):
    module_name, premises, mode, bound = task
    model = importlib.import_module(module_name)
    return model.run_model(premises, mode, bound)


def _run_shard(task):
    module_name, premises, mode, bound, prefix = task
    model = importlib.import_module(module_name)
    return model.run_model(premises, mode, bound, _trace_prefix=prefix)


def run_configurations(module_name, configurations, workers=1):
    validate_workers(workers)
    if module_name not in MODEL_MODULES:
        raise ValueError("unregistered offline model module")
    model = importlib.import_module(module_name)
    tasks = {}
    for premises, mode, bound in configurations:
        key = configuration_key(model, premises, mode, bound)
        tasks.setdefault(key, (module_name, dict(premises), mode, bound))
    if workers == 1:
        runs = [_run_configuration(task) for task in tasks.values()]
    elif module_name == "e5_model_check_two_mutations":
        shard_tasks = []
        groups = []
        for task in tasks.values():
            _, premises, mode, bound = task
            prefixes = model.shard_prefixes(premises, mode, bound)
            groups.append((premises, mode, bound, prefixes))
            shard_tasks.extend((*task, prefix) for prefix in prefixes)
        with ProcessPoolExecutor(max_workers=workers,
                                 mp_context=multiprocessing.get_context("spawn")) as executor:
            shard_runs = list(executor.map(_run_shard, shard_tasks, chunksize=1))
        runs = []
        offset = 0
        for premises, mode, bound, prefixes in groups:
            count = len(prefixes)
            runs.append(model.merge_shard_runs(
                premises, mode, bound,
                list(zip(prefixes, shard_runs[offset:offset + count])),
            ))
            offset += count
    else:
        with ProcessPoolExecutor(max_workers=workers,
                                 mp_context=multiprocessing.get_context("spawn")) as executor:
            runs = list(executor.map(_run_configuration, tasks.values(), chunksize=1))
    return dict(zip(tasks, runs))
