# Copyright(C) Facebook, Inc. and its affiliates.
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from math import ceil
from os.path import basename, splitext
from shutil import which
from time import sleep

from benchmark.imbalanced_rate import ZipfAllocator
from benchmark.commands import CommandMaker
from benchmark.config import Key, LocalCommittee, NodeParameters, BenchParameters, ConfigError
from benchmark.logs import LogParser, ParseError
from benchmark.utils import Print, BenchError, PathMaker


class LocalBench:
    BASE_PORT = 3000

    def __init__(self, bench_parameters_dict, node_parameters_dict):
        self._processes = []
        try:
            self.bench_parameters = BenchParameters(bench_parameters_dict)
            self.node_parameters = NodeParameters(node_parameters_dict)
            if bench_parameters_dict['rate_type'] == 'imbalanced':
                self.s = node_parameters_dict['s']
            self.sigma = node_parameters_dict['sigma']
            self.kappa = node_parameters_dict['kappa']
            self.reference = node_parameters_dict['reference']
            self.coverage = node_parameters_dict['coverage']
            self.allow_cross_step_weak_edges = node_parameters_dict.get(
                'allow_cross_step_weak_edges',
                True,
            )
            self.enable_fast_coin = node_parameters_dict.get(
                'enable_fast_coin',
                False,
            )
            self.solid_commit_trigger_on_solid_step = node_parameters_dict.get(
                'solid_commit_trigger_on_solid_step',
                False,
            )
            self.enable_commit_recheck = node_parameters_dict.get(
                'enable_commit_recheck',
                True,
            )
            self.fast_coin_candidate_threshold = node_parameters_dict.get(
                'fast_coin_candidate_threshold',
                0,
            )
            self.solid_candidate_threshold = node_parameters_dict.get(
                'solid_candidate_threshold',
                0,
            )
            self.design_tag = node_parameters_dict.get('design_tag')
            self.network_tag = node_parameters_dict.get('network_tag')
            self.load_tag = node_parameters_dict.get('load_tag')
        except ConfigError as e:
            raise BenchError('Invalid nodes or bench parameters', e)

    def __getattr__(self, attr):
        return getattr(self.bench_parameters, attr)

    def _background_run(self, command, log_file):
        name = splitext(basename(log_file))[0]
        cmd = f'{command} > {log_file} 2>&1'
        if which('tmux'):
            try:
                subprocess.run(['tmux', 'new', '-d', '-s', name, cmd], check=True)
                return
            except subprocess.SubprocessError:
                pass

        process = subprocess.Popen(
            cmd,
            shell=True,
            executable='/bin/bash',
            start_new_session=True,
        )
        self._processes.append(process)

    def _background_run_batch(self, launches):
        if not launches:
            return

        with ThreadPoolExecutor(max_workers=min(32, len(launches))) as executor:
            futures = [
                executor.submit(self._background_run, command, log_file)
                for command, log_file in launches
            ]
            for future in as_completed(futures):
                future.result()

    def _kill_nodes(self):
        try:
            if self._processes:
                for process in self._processes:
                    with suppress(ProcessLookupError):
                        process.terminate()
                for process in self._processes:
                    with suppress(subprocess.TimeoutExpired):
                        process.wait(timeout=5)
                self._processes = []

            if which('tmux'):
                cmd = CommandMaker.kill().split()
                subprocess.run(cmd, stderr=subprocess.DEVNULL)
        except subprocess.SubprocessError as e:
            raise BenchError('Failed to kill testbed', e)

    def run(self, debug=False):
        assert isinstance(debug, bool)
        Print.heading('Starting local benchmark')

        # Kill any previous testbed.
        self._kill_nodes()

        try:
            Print.info('Setting up testbed...')
            nodes, rate, rate_type = self.nodes[0], self.rate[0], self.rate_type
            run_dir = PathMaker.create_run_directory(
                f'local-n{nodes}-r{rate}',
                design_tag=self.design_tag,
                network_tag=self.network_tag,
                load_tag=self.load_tag,
            )
            Print.info(f'Run outputs directory: {run_dir}')

            # Cleanup all files.
            cmd = f'{CommandMaker.clean_logs()} ; {CommandMaker.cleanup()}'
            subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)
            sleep(0.5)  # Removing the store may take time.

            # Recompile the latest code.
            cmd = CommandMaker.compile().split()
            subprocess.run(cmd, check=True, cwd=PathMaker.node_crate_path())

            # Create alias for the client and nodes binary.
            cmd = CommandMaker.alias_binaries(PathMaker.binary_path())
            subprocess.run([cmd], shell=True)

            # Generate configuration files.
            keys = []
            key_files = [PathMaker.key_file(i) for i in range(nodes)]
            for filename in key_files:
                cmd = CommandMaker.generate_key(filename).split()
                subprocess.run(cmd, check=True)
                keys += [Key.from_file(filename)]

            names = [x.name for x in keys]
            committee = LocalCommittee(
                names,
                self.BASE_PORT,
                self.workers,
                self.sigma,
                self.kappa,
                self.reference,
                self.coverage,
                self.allow_cross_step_weak_edges,
                self.enable_fast_coin,
                self.solid_commit_trigger_on_solid_step,
                self.enable_commit_recheck,
                self.fast_coin_candidate_threshold,
                self.solid_candidate_threshold,
            )
            committee.print(PathMaker.committee_file())

            self.node_parameters.print(PathMaker.parameters_file())

            # Run the clients first (they will wait for the nodes to be ready).
            workers_addresses = committee.workers_addresses(self.faults)
            client_rates = []
            client_launches = []
            if rate_type == 'balanced':
                rate_share = ceil(rate / committee.workers())
                for i, addresses in enumerate(workers_addresses):
                    for (id, address) in addresses:
                        client_rates.append(rate_share)
                        cmd = CommandMaker.run_client(
                            address,
                            self.tx_size,
                            rate_share,
                            [x for y in workers_addresses for _, x in y]
                        )
                        log_file = PathMaker.client_log_file(i, id)
                        client_launches.append((cmd, log_file))
            else:
                # generate a list of rate with zipf
                zipf_allocator = ZipfAllocator(rate, committee.workers(), self.s)
                rates = zipf_allocator.allocate()
                print(rates)
                # run the clients with the generated rate
                for i, addresses in enumerate(workers_addresses):
                    for (id, address) in addresses:
                        client_rates.append(rates[i])
                        cmd = CommandMaker.run_client(
                            address,
                            self.tx_size,
                            rates[i],
                            [x for y in workers_addresses for _, x in y]
                        )
                        log_file = PathMaker.client_log_file(i, id)
                        client_launches.append((cmd, log_file))
            self._background_run_batch(client_launches)

            # Run the workers before the primaries.
            worker_launches = []
            for i, addresses in enumerate(workers_addresses):
                for (id, address) in addresses:
                    cmd = CommandMaker.run_worker(
                        PathMaker.key_file(i),
                        PathMaker.committee_file(),
                        PathMaker.db_path(i, id),
                        PathMaker.parameters_file(),
                        id,  # The worker's id.
                        debug=debug
                    )
                    log_file = PathMaker.worker_log_file(i, id)
                    worker_launches.append((cmd, log_file))
            self._background_run_batch(worker_launches)

            # Run the primaries last.
            primary_launches = []
            for i, address in enumerate(committee.primary_addresses(self.faults)):
                cmd = CommandMaker.run_primary(
                    PathMaker.key_file(i),
                    PathMaker.committee_file(),
                    PathMaker.db_path(i),
                    PathMaker.parameters_file(),
                    debug=debug
                )
                log_file = PathMaker.primary_log_file(i)
                primary_launches.append((cmd, log_file))
            self._background_run_batch(primary_launches)

            # Wait for all transactions to be processed.
            Print.info(f'Running benchmark ({self.duration} sec)...')
            sleep(self.duration)
            self._kill_nodes()

            # Parse logs and return the parser.
            Print.info('Parsing logs...')
            logger = LogParser.process(
                PathMaker.logs_path(),
                faults=self.faults,
                default_client_size=self.tx_size,
                default_client_rates=client_rates,
            )
            logger.print(PathMaker.summary_file())
            logger.print(PathMaker.result_file(
                self.faults,
                nodes,
                self.workers,
                True,
                rate,
                self.tx_size,
            ))
            PathMaker.export_run_artifacts()
            return logger

        except (subprocess.SubprocessError, ParseError) as e:
            self._kill_nodes()
            raise BenchError('Failed to run benchmark', e)
