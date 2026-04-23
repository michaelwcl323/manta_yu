# Copyright(C) Facebook, Inc. and its affiliates.
import json
import os
import re
import shutil
from datetime import datetime
from os import makedirs
from os.path import dirname
from os.path import join


class BenchError(Exception):
    def __init__(self, message, error):
        assert isinstance(error, Exception)
        self.message = message
        self.cause = error
        super().__init__(message)


class PathMaker:
    RUN_DIR_ENV = 'MANTA_RUN_DIR'
    LATEST_RUN_FILE = '.latest_run'

    @staticmethod
    def _tag_segment(value, default):
        value = str(value).strip() if value is not None else ''
        value = value.replace(' ', '_')
        return value or default

    @staticmethod
    def _sanitize_label(label):
        label = re.sub(r'[^A-Za-z0-9._-]+', '-', label.strip())
        return label.strip('-') or 'run'

    @staticmethod
    def binary_path():
        return join('..', 'target', 'release')

    @staticmethod
    def node_crate_path():
        return join('..', 'node')

    @staticmethod
    def committee_file():
        return '.committee.json'

    @staticmethod
    def parameters_file():
        return '.parameters.json'

    @staticmethod
    def key_file(i):
        assert isinstance(i, int) and i >= 0
        return f'.node-{i}.json'

    @staticmethod
    def db_path(i, j=None):
        assert isinstance(i, int) and i >= 0
        assert (isinstance(j, int) and i >= 0) or j is None
        worker_id = f'-{j}' if j is not None else ''
        return f'.db-{i}{worker_id}'

    @staticmethod
    def logs_path():
        run_dir = PathMaker.current_run_path()
        return join(run_dir, 'logs') if run_dir else 'logs'

    @staticmethod
    def reset_logs_path():
        logs_dir = PathMaker.logs_path()
        if os.path.isdir(logs_dir):
            shutil.rmtree(logs_dir)
        os.makedirs(logs_dir, exist_ok=True)
        return logs_dir

    @staticmethod
    def primary_log_file(i):
        assert isinstance(i, int) and i >= 0
        return join(PathMaker.logs_path(), f'primary-{i}.log')

    @staticmethod
    def worker_log_file(i, j):
        assert isinstance(i, int) and i >= 0
        assert isinstance(j, int) and i >= 0
        return join(PathMaker.logs_path(), f'worker-{i}-{j}.log')

    @staticmethod
    def client_log_file(i, j):
        assert isinstance(i, int) and i >= 0
        assert isinstance(j, int) and i >= 0
        return join(PathMaker.logs_path(), f'client-{i}-{j}.log')

    @staticmethod
    def results_path():
        run_dir = PathMaker.current_run_path()
        return run_dir if run_dir else 'results'

    @staticmethod
    def base_results_path():
        return 'manta_result'

    @staticmethod
    def tagged_results_path(design_tag=None, network_tag=None, load_tag=None):
        parts = [PathMaker.base_results_path()]
        for tag in (design_tag, network_tag, load_tag):
            if tag is not None:
                parts.append(PathMaker._sanitize_label(str(tag)))
        return join(*parts)

    @staticmethod
    def latest_run_file():
        return join(PathMaker.base_results_path(), PathMaker.LATEST_RUN_FILE)

    @staticmethod
    def current_run_path():
        run_dir = os.environ.get(PathMaker.RUN_DIR_ENV)
        if run_dir:
            return run_dir

        latest_run_file = PathMaker.latest_run_file()
        if os.path.exists(latest_run_file):
            with open(latest_run_file, 'r') as f:
                run_dir = f.read().strip()
            return run_dir or None
        return None

    @staticmethod
    def activate_run_directory(run_dir):
        assert isinstance(run_dir, str) and run_dir
        os.makedirs(run_dir, exist_ok=True)
        os.environ[PathMaker.RUN_DIR_ENV] = run_dir

        os.makedirs(PathMaker.base_results_path(), exist_ok=True)
        with open(PathMaker.latest_run_file(), 'w') as f:
            f.write(run_dir)
        return run_dir

    @staticmethod
    def run_metadata_file(run_dir=None):
        run_dir = run_dir or PathMaker.current_run_path()
        return join(run_dir, 'run_metadata.json') if run_dir else None

    @staticmethod
    def load_run_metadata(run_dir=None):
        metadata_file = PathMaker.run_metadata_file(run_dir)
        if metadata_file is None or not os.path.exists(metadata_file):
            return {}

        with open(metadata_file, 'r') as f:
            return json.load(f)

    @staticmethod
    def update_run_metadata(extra_metadata, run_dir=None):
        assert isinstance(extra_metadata, dict)

        run_dir = run_dir or PathMaker.current_run_path()
        if not run_dir:
            return {}

        os.makedirs(run_dir, exist_ok=True)
        metadata = PathMaker.load_run_metadata(run_dir)
        for key, value in extra_metadata.items():
            if isinstance(value, dict) and isinstance(metadata.get(key), dict):
                metadata[key].update(value)
            else:
                metadata[key] = value

        metadata_file = PathMaker.run_metadata_file(run_dir)
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
            f.write('\n')
        return metadata

    @staticmethod
    def create_run_directory(
        label='run',
        design_tag=None,
        network_tag=None,
        load_tag=None,
    ):
        safe_label = PathMaker._sanitize_label(label)
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')
        base_dir = PathMaker.tagged_results_path(
            design_tag=design_tag,
            network_tag=network_tag,
            load_tag=load_tag,
        )
        os.makedirs(base_dir, exist_ok=True)

        run_dir = join(base_dir, f'{timestamp}_{safe_label}')
        counter = 1
        while os.path.exists(run_dir):
            counter += 1
            run_dir = join(base_dir, f'{timestamp}_{safe_label}_{counter}')

        PathMaker.activate_run_directory(run_dir)
        PathMaker.update_run_metadata(
            {
                'created_at_utc': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
                'label': safe_label,
                'run_dir': run_dir,
                'design_tag': PathMaker._sanitize_label(str(design_tag))
                if design_tag is not None
                else None,
                'network_tag': PathMaker._sanitize_label(str(network_tag))
                if network_tag is not None
                else None,
                'load_tag': PathMaker._sanitize_label(str(load_tag))
                if load_tag is not None
                else None,
            },
            run_dir=run_dir,
        )
        return run_dir

    @staticmethod
    def summary_path(design_tag=None, network_tag=None):
        return join(
            PathMaker._tag_segment(design_tag, 'untagged_design'),
            PathMaker._tag_segment(network_tag, 'untagged_network'),
        )

    @staticmethod
    def summary_file(
        faults,
        nodes,
        workers,
        collocate,
        rate,
        tx_size,
        run,
        design_tag=None,
        network_tag=None,
        timestamp=None,
    ):
        design_segment = PathMaker._tag_segment(design_tag, 'untagged_design')
        network_segment = PathMaker._tag_segment(network_tag, 'untagged_network')
        stamp = timestamp or datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = (
            f'summary_design-{design_segment}_network-{network_segment}'
            f'_f{faults}_n{nodes}_w{workers}_c{collocate}'
            f'_r{rate}_tx{tx_size}_run{run}_{stamp}.txt'
        )
        run_dir = PathMaker.current_run_path()
        return join(run_dir, filename) if run_dir else join(
            PathMaker.summary_path(design_segment, network_segment),
            filename,
        )

    @staticmethod
    def plots_path():
        return 'plots'

    @staticmethod
    def agg_file(type, faults, nodes, workers, collocate, rate, tx_size, max_latency=None):
        if max_latency is None:
            name = f'{type}-bench-{faults}-{nodes}-{workers}-{collocate}-{rate}-{tx_size}.txt'
        else:
            name = f'{type}-{max_latency}-bench-{faults}-{nodes}-{workers}-{collocate}-{rate}-{tx_size}.txt'
        return join(PathMaker.plots_path(), name)

    @staticmethod
    def plot_file(name, ext):
        return join(PathMaker.plots_path(), f'{name}.{ext}')

    @staticmethod
    def export_run_artifacts():
        return {}


class Color:
    HEADER = '\033[95m'
    OK_BLUE = '\033[94m'
    OK_GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Print:
    @staticmethod
    def heading(message):
        assert isinstance(message, str)
        print(f'{Color.OK_GREEN}{message}{Color.END}')

    @staticmethod
    def info(message):
        assert isinstance(message, str)
        print(message)

    @staticmethod
    def warn(message):
        assert isinstance(message, str)
        print(f'{Color.BOLD}{Color.WARNING}WARN{Color.END}: {message}')

    @staticmethod
    def error(e):
        assert isinstance(e, BenchError)
        print(f'\n{Color.BOLD}{Color.FAIL}ERROR{Color.END}: {e}\n')
        causes, current_cause = [], e.cause
        while isinstance(current_cause, BenchError):
            causes += [f'  {len(causes)}: {e.cause}\n']
            current_cause = current_cause.cause
        causes += [f'  {len(causes)}: {type(current_cause)}\n']
        causes += [f'  {len(causes)}: {current_cause}\n']
        print(f'Caused by: \n{"".join(causes)}\n')


def write_failure_summary(
    filename,
    *,
    design_tag,
    network_tag,
    faults,
    nodes,
    workers,
    collocate,
    rate,
    tx_size,
    run,
    error,
):
    assert isinstance(filename, str)
    parent = dirname(filename)
    if parent:
        makedirs(parent, exist_ok=True)

    content = (
        '\n'
        '-----------------------------------------\n'
        ' SUMMARY:\n'
        '-----------------------------------------\n'
        ' + CONFIG:\n'
        f' Design tag: {design_tag or "N/A"}\n'
        f' Network tag: {network_tag or "N/A"}\n'
        f' Faults: {faults} node(s)\n'
        f' Committee size: {nodes} node(s)\n'
        f' Worker(s) per node: {workers} worker(s)\n'
        f' Collocate primary and workers: {collocate}\n'
        f' Input rate: {rate:,} tx/s\n'
        f' Transaction size: {tx_size:,} B\n'
        f' Run: {run}\n'
        '\n'
        ' + RESULTS:\n'
        ' Status: FAILED\n'
        f' Error: {error}\n'
        '-----------------------------------------\n'
    )

    with open(filename, 'w') as f:
        f.write(content)


def progress_bar(iterable, prefix='', suffix='', decimals=1, length=30, fill='█', print_end='\r'):
    total = len(iterable)

    def printProgressBar(iteration):
        formatter = '{0:.'+str(decimals)+'f}'
        percent = formatter.format(100 * (iteration / float(total)))
        filledLength = int(length * iteration // total)
        bar = fill * filledLength + '-' * (length - filledLength)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)

    printProgressBar(0)
    for i, item in enumerate(iterable):
        yield item
        printProgressBar(i + 1)
    print()
