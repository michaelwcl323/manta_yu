# Copyright(C) Facebook, Inc. and its affiliates.
import csv
import os
from datetime import datetime
from glob import glob
from multiprocessing import Pool
from os.path import join
from re import findall, search
from statistics import mean

from benchmark.utils import PathMaker, Print


class ParseError(Exception):
    pass


def parse_primary_boot_wall_time(log: str):
    """Parse wall-clock time of ``Primary … successfully booted on`` (env_logger formats).

    Matches ``node`` default logging with ``format_timestamp_millis()`` (fractional seconds,
    often without a trailing ``Z`` in the timestamp token).
    """
    for line in log.splitlines():
        if 'successfully booted on' not in line or 'Primary' not in line:
            continue
        inner = search(r'\[([^\]]+)\]', line)
        if not inner:
            continue
        head = inner.group(1)
        ts_token = (
            head.split(' INFO', 1)[0]
            .split(' WARN', 1)[0]
            .split(' ERROR', 1)[0]
            .split(' DEBUG', 1)[0]
            .split(' TRACE', 1)[0]
            .strip()
        )
        ts_norm = ts_token.replace(' ', 'T')
        if not ts_norm:
            continue
        try:
            x = datetime.fromisoformat(ts_norm.replace('Z', '+00:00'))
            return datetime.timestamp(x)
        except ValueError:
            continue
    return None


class LogParser:
    def __init__(self, clients, primaries, workers, faults=0,
                 default_client_size=None, default_client_rates=None):
        inputs = [clients, primaries, workers]
        assert all(isinstance(x, list) for x in inputs)
        assert all(isinstance(x, str) for y in inputs for x in y)
        assert all(x for x in inputs)

        self.faults = faults
        if isinstance(faults, int):
            self.committee_size = len(primaries) + int(faults)
            self.workers =  len(workers) // len(primaries)
        else:
            self.committee_size = '?'
            self.workers = '?'

        # Parse the clients logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_clients, clients)
        except (ValueError, IndexError, AttributeError) as e:
            if default_client_size is None or default_client_rates is None:
                raise ParseError(f'Failed to parse clients\' logs: {e}')

            rates = default_client_rates
            if not isinstance(rates, list):
                rates = [rates] * len(clients)
            if len(rates) != len(clients):
                raise ParseError('Failed to parse clients\' logs: mismatched fallback rates')

            Print.warn(
                'Client logs are missing the expected metadata; '
                'falling back to configured transaction size/rate values'
            )
            results = [
                (default_client_size, rates[i], None, 0, {})
                for i in range(len(clients))
            ]
        self.size, self.rate, self.start, misses, self.sent_samples \
            = zip(*results)
        self.misses = sum(misses)

        # Parse the primaries logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_primaries, primaries)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse nodes\' logs: {e}')
        proposals, commits, self.configs, primary_ips, primary_boots = zip(*results)
        self.proposals = self._merge_results([x.items() for x in proposals])
        self.commits = self._merge_results([x.items() for x in commits])
        self.primary_boot_times = list(primary_boots)

        # Parse the workers logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_workers, workers)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse workers\' logs: {e}')
        sizes, self.received_samples, workers_ips = zip(*results)
        self.sizes = {
            k: v for x in sizes for k, v in x.items() if k in self.commits
        }

        # Determine whether the primary and the workers are collocated.
        self.collocate = set(primary_ips) == set(workers_ips)

        # Check whether clients missed their target rate.
        if self.misses != 0:
            Print.warn(
                f'Clients missed their target rate {self.misses:,} time(s)'
            )

        self._matched_end_to_end_samples_cache = None
        self._missing_end_to_end_samples = None

    def _merge_results(self, input):
        # Keep the earliest timestamp.
        merged = {}
        for x in input:
            for k, v in x:
                if not k in merged or merged[k] > v:
                    merged[k] = v
        return merged

    def _parse_clients(self, log):
        if search(r'Error', log) is not None:
            raise ParseError('Client(s) panicked')

        size = int(search(r'Transactions size: (\d+)', log).group(1))
        rate = int(search(r'Transactions rate: (\d+)', log).group(1))

        tmp = search(r'\[(.*Z) .* Start ', log).group(1)
        start = self._to_posix(tmp)

        misses = len(findall(r'rate too high', log))

        tmp = findall(r'\[(.*Z) .* sample transaction (\d+)', log)
        samples = {int(s): self._to_posix(t) for t, s in tmp}

        return size, rate, start, misses, samples

    def _parse_primaries(self, log):
        if search(r'(?:panicked|Error)', log) is not None:
            raise ParseError('Primary(s) panicked')

        tmp = findall(r'\[(.*Z) .* Created B\d+\([^ ]+\) -> ([^ ]+=)', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        proposals = self._merge_results([tmp])

        tmp = findall(r'\[(.*Z) .* Committed B\d+\([^ ]+\) -> ([^ ]+=)', log)
        tmp = [(d, self._to_posix(t)) for t, d in tmp]
        commits = self._merge_results([tmp])

        configs = {
            'header_size': int(
                search(r'Header size .* (\d+)', log).group(1)
            ),
            'max_header_delay': int(
                search(r'Max header delay .* (\d+)', log).group(1)
            ),
            'gc_depth': int(
                search(r'Garbage collection depth .* (\d+)', log).group(1)
            ),
            'sync_retry_delay': int(
                search(r'Sync retry delay .* (\d+)', log).group(1)
            ),
            'sync_retry_nodes': int(
                search(r'Sync retry nodes .* (\d+)', log).group(1)
            ),
            'batch_size': int(
                search(r'Batch size .* (\d+)', log).group(1)
            ),
            'max_batch_delay': int(
                search(r'Max batch delay .* (\d+)', log).group(1)
            ),
        }

        ip = search(r'booted on (\d+.\d+.\d+.\d+)', log).group(1)

        primary_boot_ts = parse_primary_boot_wall_time(log)

        return proposals, commits, configs, ip, primary_boot_ts

    def _parse_workers(self, log):
        if search(r'(?:panic|Error)', log) is not None:
            raise ParseError('Worker(s) panicked')

        tmp = findall(r'Batch ([^ ]+) contains (\d+) B', log)
        sizes = {d: int(s) for d, s in tmp}

        tmp = findall(r'Batch ([^ ]+) contains sample tx (\d+)', log)
        samples = {int(s): d for d, s in tmp}

        ip = search(r'booted on (\d+.\d+.\d+.\d+)', log).group(1)

        return sizes, samples, ip

    def _to_posix(self, string):
        x = datetime.fromisoformat(string.replace('Z', '+00:00'))
        return datetime.timestamp(x)

    def _committed_batch_ids(self, require_proposal=False):
        batch_ids = list(self.sizes.keys())
        if require_proposal:
            batch_ids = [digest for digest in batch_ids if digest in self.proposals]
        return batch_ids

    def _consensus_throughput(self):
        batch_ids = self._committed_batch_ids(require_proposal=True)
        if not batch_ids:
            return 0, 0, 0
        # Only use batches for which we observed proposal, commit, and size.
        # This avoids stretching the consensus window with proposals unrelated
        # to the bytes counted in the throughput numerator.
        start = min(self.proposals[digest] for digest in batch_ids)
        end = max(self.commits[digest] for digest in batch_ids)
        duration = max(end - start, 1e-9)
        bytes = sum(self.sizes[digest] for digest in batch_ids)
        bps = bytes / duration
        tps = bps / self.size[0]
        return tps, bps, duration

    def _consensus_latency(self):
        latency = [
            self.commits[digest] - self.proposals[digest]
            for digest in self._committed_batch_ids(require_proposal=True)
        ]
        return mean(latency) if latency else 0

    def execution_origin_unix(self):
        """Wall-clock max primary ``successfully booted`` time (subset of execution T0 logic)."""
        boots = [t for t in self.primary_boot_times if t is not None]
        if not boots:
            return None
        return max(boots)

    def execution_time_window(self):
        """``(start_unix, end_unix, duration_s)`` — same window as Summary *Execution time* / E2E TPS.

        ``start_unix`` is the single source of truth for ``relative_time_s`` in ``latency.csv`` and
        for latency plot axes (``execution_time_start_unix`` in ``run_metadata.json``).
        """
        batch_ids = self._committed_batch_ids()
        if not batch_ids:
            return None
        end = max(self.commits[digest] for digest in batch_ids)
        primary_start = self.execution_origin_unix()
        proposal_times = [
            self.proposals[d]
            for d in batch_ids
            if d in self.proposals
        ]
        chain_start = min(proposal_times) if proposal_times else None
        if primary_start is not None:
            start = primary_start
        elif chain_start is not None:
            start = chain_start
        else:
            start_candidates = [x for x in self.start if x is not None]
            if start_candidates:
                start = min(start_candidates)
            else:
                start = min(self.commits[digest] for digest in batch_ids)
        duration = max(end - start, 1e-9)
        return float(start), float(end), float(duration)

    def _end_to_end_throughput(self):
        w = self.execution_time_window()
        if not w:
            return 0, 0, 0
        start, end, duration = w
        batch_ids = self._committed_batch_ids()
        bytes = sum(self.sizes[digest] for digest in batch_ids)
        bps = bytes / duration
        tps = bps / self.size[0]
        return tps, bps, duration

    def _matched_end_to_end_samples(self):
        if self._matched_end_to_end_samples_cache is not None:
            return self._matched_end_to_end_samples_cache

        matched = []
        missing = 0
        for client_index, (sent, received) in enumerate(
            zip(self.sent_samples, self.received_samples)
        ):
            for tx_id, batch_id in received.items():
                commit_ts = self.commits.get(batch_id)
                if commit_ts is None:
                    continue

                start_ts = sent.get(tx_id)
                if start_ts is None:
                    missing += 1
                    continue

                matched.append((client_index, tx_id, start_ts, commit_ts))

        self._matched_end_to_end_samples_cache = matched
        self._missing_end_to_end_samples = missing
        return matched

    def _end_to_end_latency(self):
        latency = [
            commit_ts - start_ts
            for _, _, start_ts, commit_ts in self._matched_end_to_end_samples()
        ]
        return mean(latency) if latency else 0

    def result(self):
        header_size = self.configs[0]['header_size']
        max_header_delay = self.configs[0]['max_header_delay']
        gc_depth = self.configs[0]['gc_depth']
        sync_retry_delay = self.configs[0]['sync_retry_delay']
        sync_retry_nodes = self.configs[0]['sync_retry_nodes']
        batch_size = self.configs[0]['batch_size']
        max_batch_delay = self.configs[0]['max_batch_delay']
        run_metadata = PathMaker.load_run_metadata()
        node_params = run_metadata.get('node_params', {})

        extra_config_lines = ''
        if run_metadata.get('execution_time_start_unix') is not None:
            extra_config_lines += (
                f' Execution time T0 (unix): {run_metadata["execution_time_start_unix"]}\n'
                f' Execution time end (unix): {run_metadata.get("execution_time_end_unix")}\n'
            )
        for label, key in (
            ('Sigma', 'sigma'),
            ('Kappa', 'kappa'),
            ('Reference', 'reference'),
            ('Coverage', 'coverage'),
            ('Allow cross-step weak edges', 'allow_cross_step_weak_edges'),
            ('Enable fast coin', 'enable_fast_coin'),
            (
                'Solid commit trigger on solid step',
                'solid_commit_trigger_on_solid_step',
            ),
            ('Enable commit recheck', 'enable_commit_recheck'),
            ('Fast coin candidate threshold', 'fast_coin_candidate_threshold'),
            ('Solid candidate threshold', 'solid_candidate_threshold'),
            ('Attack enabled', 'attack_enabled'),
            ('Attack start seconds', 'attack_start_secs'),
            ('Attack duration seconds', 'attack_duration_secs'),
            ('Attack group size', 'attack_group_size'),
            ('Attack limit headers', 'attack_limit_headers'),
            ('Attack limit certificates', 'attack_limit_certificates'),
            ('Enable adaptive intermediate spill', 'enable_adaptive_intermediate_spill'),
            (
                'Adaptive intermediate spill trigger digests',
                'adaptive_intermediate_spill_trigger_digests',
            ),
            (
                'Adaptive intermediate spill cap digests',
                'adaptive_intermediate_spill_cap_digests',
            ),
            ('Design tag', 'design_tag'),
            ('Network tag', 'network_tag'),
            ('Load tag', 'load_tag'),
        ):
            value = node_params.get(key)
            if value is not None:
                extra_config_lines += f' {label}: {value}\n'

        consensus_batch_ids = self._committed_batch_ids(require_proposal=True)
        committed_batch_ids = self._committed_batch_ids()
        consensus_latency = self._consensus_latency() * 1_000
        consensus_tps, consensus_bps, _ = self._consensus_throughput()
        end_to_end_tps, end_to_end_bps, duration = self._end_to_end_throughput()
        end_to_end_latency = self._end_to_end_latency() * 1_000
        missing_end_to_end_samples = self._missing_end_to_end_samples or 0
        sample_warning = ''
        if missing_end_to_end_samples:
            sample_warning = (
                f' Skipped end-to-end samples missing client send timestamps: '
                f'{missing_end_to_end_samples:,}\n'
            )

        zero_result_reason = ''
        if not committed_batch_ids:
            zero_result_reason = (
                ' Result note: no committed vertices were observed in the primary logs; '
                'zero throughput/latency values below indicate no commits, not measured latency.\n'
            )
        elif not consensus_batch_ids:
            zero_result_reason = (
                ' Result note: committed vertices were observed, but no batches had both '
                'proposal and commit timestamps, so consensus metrics are reported as 0.\n'
            )

        return (
            '\n'
            '-----------------------------------------\n'
            ' SUMMARY:\n'
            '-----------------------------------------\n'
            ' + CONFIG:\n'
            f' Faults: {self.faults} node(s)\n'
            f' Committee size: {self.committee_size} node(s)\n'
            f' Worker(s) per node: {self.workers} worker(s)\n'
            f' Collocate primary and workers: {self.collocate}\n'
            f' Input rate: {sum(self.rate):,} tx/s\n'
            f' Transaction size: {self.size[0]:,} B\n'
            f' Execution time: {round(duration):,} s (same T0 as latency.csv / plots; see run_metadata execution_time_*)\n'
            '\n'
            f' Header size: {header_size:,} B\n'
            f' Max header delay: {max_header_delay:,} ms\n'
            f' GC depth: {gc_depth:,} round(s)\n'
            f' Sync retry delay: {sync_retry_delay:,} ms\n'
            f' Sync retry nodes: {sync_retry_nodes:,} node(s)\n'
            f' batch size: {batch_size:,} B\n'
            f' Max batch delay: {max_batch_delay:,} ms\n'
            f'{extra_config_lines}'
            '\n'
            ' + RESULTS:\n'
            f'{zero_result_reason}'
            f' Consensus TPS: {round(consensus_tps):,} tx/s\n'
            f' Consensus BPS: {round(consensus_bps):,} B/s\n'
            f' Consensus latency: {round(consensus_latency):,} ms\n'
            '\n'
            f' End-to-end TPS: {round(end_to_end_tps):,} tx/s\n'
            f' End-to-end BPS: {round(end_to_end_bps):,} B/s\n'
            f' End-to-end latency: {round(end_to_end_latency):,} ms\n'
            f'{sample_warning}'
            '-----------------------------------------\n'
        )

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'a') as f:
            f.write(self.result())

    def export_latency_csv(self, filename=None):
        filename = filename or PathMaker.latency_csv_file()
        rows = []
        win = self.execution_time_window()
        baseline_ts = win[0] if win else None
        if baseline_ts is None:
            baseline_candidates = [
                self.proposals[digest]
                for digest in self._committed_batch_ids(require_proposal=True)
                if digest in self.proposals
            ]
            if baseline_candidates:
                baseline_ts = min(baseline_candidates)
            else:
                commit_candidates = [ts for _, ts in self.commits.items()]
                baseline_ts = min(commit_candidates) if commit_candidates else None

        for batch_id, commit_ts in sorted(self.commits.items(), key=lambda item: item[1]):
            proposal_ts = self.proposals.get(batch_id)
            if proposal_ts is None:
                continue
            rows.append({
                'metric': 'consensus_latency',
                'identifier': batch_id,
                'proposal_ts': round(proposal_ts, 6),
                'commit_ts': round(commit_ts, 6),
                'relative_time_s': round(commit_ts - baseline_ts, 6) if baseline_ts is not None else '',
                'latency_ms': round((commit_ts - proposal_ts) * 1000, 3),
            })

        for client_index, tx_id, start_ts, commit_ts in self._matched_end_to_end_samples():
            rows.append({
                'metric': 'end_to_end_latency',
                'identifier': f'{client_index}:{tx_id}',
                'proposal_ts': round(start_ts, 6),
                'commit_ts': round(commit_ts, 6),
                'relative_time_s': round(commit_ts - baseline_ts, 6) if baseline_ts is not None else '',
                'latency_ms': round((commit_ts - start_ts) * 1000, 3),
            })

        if not rows:
            return None

        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    'metric',
                    'identifier',
                    'proposal_ts',
                    'commit_ts',
                    'relative_time_s',
                    'latency_ms',
                ],
            )
            writer.writeheader()
            writer.writerows(rows)
        return filename

    @classmethod
    def process(cls, directory, faults=0, default_client_size=None,
                default_client_rates=None):
        assert isinstance(directory, str)

        clients = []
        for filename in sorted(glob(join(directory, 'client-*.log'))):
            with open(filename, 'r') as f:
                clients += [f.read()]
        primaries = []
        for filename in sorted(glob(join(directory, 'primary-*.log'))):
            with open(filename, 'r') as f:
                primaries += [f.read()]
        workers = []
        for filename in sorted(glob(join(directory, 'worker-*.log'))):
            with open(filename, 'r') as f:
                workers += [f.read()]

        return cls(
            clients,
            primaries,
            workers,
            faults=faults,
            default_client_size=default_client_size,
            default_client_rates=default_client_rates,
        )
