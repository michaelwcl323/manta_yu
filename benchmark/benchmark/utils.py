# Copyright(C) Facebook, Inc. and its affiliates.
import csv
import json
import os
import re
import shutil
from datetime import datetime
from glob import glob
from os.path import join

from benchmark.dag_vis import (
    build_annotated_dag_snapshot,
    collect_best_round_snapshots,
    export_dag_event_csv,
    export_dag_overview_json,
)


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
        return join(PathMaker.base_results_path(), 'logs')

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
        return PathMaker.output_path()

    @staticmethod
    def result_file(faults, nodes, workers, collocate, rate, tx_size):
        return join(
            PathMaker.results_path(),
            f'bench-{faults}-{nodes}-{workers}-{collocate}-{rate}-{tx_size}.txt'
        )

    @staticmethod
    def summary_file():
        return join(PathMaker.results_path(), 'summary.txt')

    @staticmethod
    def latency_csv_file():
        return join(PathMaker.results_path(), 'latency.csv')

    @staticmethod
    def final_dag_file():
        return join(PathMaker.results_path(), 'final_dag.txt')

    @staticmethod
    def solid_step_vertices_csv_file():
        return join(PathMaker.results_path(), 'solid_step_vertices.csv')

    @staticmethod
    def dag_events_csv_file():
        return join(PathMaker.results_path(), 'dag_events.csv')

    @staticmethod
    def dag_overview_json_file():
        return join(PathMaker.results_path(), 'dag_overview.json')

    @staticmethod
    def dag_overview_html_file():
        return join(PathMaker.results_path(), 'dag_overview.html')

    @staticmethod
    def plots_path():
        return join(PathMaker.base_results_path(), 'plots')

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
    def base_results_path():
        return 'manta_result'

    @staticmethod
    def design_tag_results_path(design_tag=None):
        return PathMaker.tagged_results_path(design_tag=design_tag)

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
    def run_metadata_file(run_dir=None):
        run_dir = run_dir or PathMaker.current_run_path()
        return join(run_dir, 'run_metadata.json') if run_dir else None

    @staticmethod
    def run_logs_path(run_dir=None):
        run_dir = run_dir or PathMaker.current_run_path()
        return join(run_dir, 'logs') if run_dir else None

    @staticmethod
    def output_path():
        return PathMaker.current_run_path() or PathMaker.base_results_path()

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
    def _sanitize_label(label):
        label = re.sub(r'[^A-Za-z0-9._-]+', '-', label.strip())
        return label.strip('-') or 'run'

    @staticmethod
    def create_run_directory(
        label='run',
        design_tag=None,
        network_tag=None,
        load_tag=None,
    ):
        safe_label = PathMaker._sanitize_label(label)
        
        # Check if custom folder prefix is provided via environment variable
        custom_prefix = os.environ.get('MANTA_FOLDER_PREFIX')
        if custom_prefix:
            timestamp = PathMaker._sanitize_label(custom_prefix)
        else:
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
    def all_result_files():
        pattern = join(PathMaker.base_results_path(), '**', 'bench-*.txt')
        return sorted(set(glob(pattern, recursive=True)))

    @staticmethod
    def export_run_artifacts():
        artifacts = {}
        run_dir = PathMaker.current_run_path()
        if not run_dir:
            return artifacts

        source_logs_dir = PathMaker.logs_path()
        target_logs_dir = PathMaker.run_logs_path(run_dir)
        if os.path.isdir(source_logs_dir) and target_logs_dir:
            if os.path.isdir(target_logs_dir):
                shutil.rmtree(target_logs_dir)
            shutil.copytree(source_logs_dir, target_logs_dir)
            artifacts['logs_dir'] = target_logs_dir

            primary0_log = join(target_logs_dir, 'primary-0.log')
            if os.path.exists(primary0_log):
                artifacts['primary0_log'] = primary0_log

        if artifacts:
            PathMaker.update_run_metadata({'artifacts': artifacts}, run_dir=run_dir)

        # DAG-related exports are useful for debugging, but they re-scan large
        # primary logs and noticeably slow down benchmark post-processing.
        # Keep them disabled by default during parameter sweeps.
        return artifacts

    @staticmethod
    def export_final_dag(log_files=None, output_file=None):
        log_files = log_files or sorted(glob(join(PathMaker.logs_path(), 'primary-*.log')))
        best = collect_best_round_snapshots(log_files)

        if not best:
            return None

        output_file = output_file or PathMaker.final_dag_file()
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            for round_num in sorted(best):
                f.write(f"Round {round_num}: {best[round_num]['raw']}")
                f.write('\n')
        return output_file

    @staticmethod
    def export_solid_step_vertices_csv(log_files=None, output_file=None):
        log_files = log_files or sorted(glob(join(PathMaker.logs_path(), 'primary-*.log')))
        line_re = re.compile(
            r"\[(?P<ts>[^]]+)\s+DEBUG\s+primary::(?:proposer|aggregators)\]\s+"
            r"Current round:\s+(?P<round>\d+),\s+"
            r"(?:(?:The number of (?:merged )?solid-step vertices is)\s+|solid_step_vertices=)"
            r"(?P<count>\d+)"
        )
        max_by_key = {}

        for path in log_files:
            if not os.path.exists(path):
                continue
            primary_name = os.path.splitext(os.path.basename(path))[0]
            with open(path, 'r', errors='replace') as f:
                for line in f:
                    match = line_re.search(line)
                    if not match:
                        continue
                    round_num = int(match.group('round'))
                    count = int(match.group('count'))
                    ts = match.group('ts')
                    key = (primary_name, round_num)
                    existing = max_by_key.get(key)
                    if existing is None or count > existing['solid_step_vertices']:
                        max_by_key[key] = {
                            'primary': primary_name,
                            'timestamp': ts,
                            'round': round_num,
                            'solid_step_vertices': count,
                        }
                    elif count == existing['solid_step_vertices'] and ts > existing['timestamp']:
                        existing['timestamp'] = ts

        if not max_by_key:
            return None

        output_file = output_file or PathMaker.solid_step_vertices_csv_file()
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=['primary', 'timestamp', 'round', 'solid_step_vertices'],
            )
            writer.writeheader()
            for row in sorted(
                max_by_key.values(),
                key=lambda item: (item['round'], item['primary'], item['timestamp']),
            ):
                writer.writerow(row)
        return output_file

    @staticmethod
    def export_annotated_dag_artifacts(log_files=None, final_dag_file=None):
        log_files = log_files or sorted(glob(join(PathMaker.logs_path(), 'primary-*.log')))
        final_dag_file = final_dag_file or PathMaker.final_dag_file()
        if not log_files or not final_dag_file or not os.path.exists(final_dag_file):
            return {}

        snapshot = build_annotated_dag_snapshot(final_dag_file, log_files)
        if not snapshot['rounds']:
            return {}

        artifacts = {}

        dag_events_csv = export_dag_event_csv(log_files, PathMaker.dag_events_csv_file())
        if dag_events_csv:
            artifacts['dag_events_csv'] = dag_events_csv

        dag_overview_json = export_dag_overview_json(
            snapshot, PathMaker.dag_overview_json_file()
        )
        if dag_overview_json:
            artifacts['dag_overview_json'] = dag_overview_json

        return artifacts


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
