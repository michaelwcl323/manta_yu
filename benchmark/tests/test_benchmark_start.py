import ast
import unittest
from pathlib import Path
from benchmark.logs import LogParser


class BenchmarkStartTests(unittest.TestCase):
    def parser(self):
        parser = LogParser.__new__(LogParser)
        parser.primary_boot_times = [90, 95]
        parser.start = [101, 103]
        parser.proposals = {'batch': 104}
        parser.commits = {'batch': 120}
        parser.sizes = {'batch': 512}
        return parser

    def test_release_time_excludes_startup_and_client_scheduling_skew(self):
        parser = self.parser()
        parser.benchmark_start_unix = 100
        self.assertEqual(parser.execution_time_window(), (100, 120, 20))

    def test_legacy_logs_still_use_client_start(self):
        self.assertEqual(self.parser().execution_time_window(), (101, 120, 19))

    def test_attack_uses_release_instead_of_primary_boot(self):
        path = Path(__file__).parents[1] / 'plot_attack_latency_timeseries.py'
        tree = ast.parse(path.read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in ('execution_time_axis_t0', 'get_attack_window')]
        scope = {}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), 'exec'), scope)
        metadata = {'benchmark_start_unix': 100, 'execution_time_start_unix': 100,
                    'execution_origin_unix': 90,
                    'node_params': {'attack_enabled': True, 'attack_start_secs': 60}}
        self.assertEqual(scope['get_attack_window'](metadata, None, None)['start'], 60)

    def test_controller_releases_only_after_all_readiness_checks(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from benchmark.cloudlab_remote import CloudLabBench
        events = []

        class Connection:
            def __init__(self, host, **kwargs):
                self.host = host
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def run(self, command, **kwargs):
                events.append(('ready' if command.startswith('grep') else 'release', self.host))
                return SimpleNamespace(ok=True)
            def put(self, data, remote):
                events.append(('timestamp', data.read()))

        bench = CloudLabBench.__new__(CloudLabBench)
        bench.settings = SimpleNamespace(repo_name='test')
        bench._benchmark_start_file = '.start-test'
        bench._get_connection_kwargs = lambda host: {}
        jobs = [({'hostname': str(i)}, 'log', 'ready') for i in range(3)]
        with patch('benchmark.cloudlab_remote.Connection', Connection), \
             patch('benchmark.cloudlab_remote.PathMaker.update_run_metadata'), \
             patch('time.sleep'), patch('time.time', return_value=100):
            bench._release_benchmark(jobs)
        self.assertEqual([x[0] for x in events[:3]], ['ready'] * 3)
        self.assertEqual([x[1] for x in events if x[0] == 'timestamp'], [b'115000'] * 3)

    def test_failed_readiness_never_releases_clients(self):
        from types import SimpleNamespace
        from unittest.mock import patch, Mock
        from benchmark.cloudlab_remote import CloudLabBench
        from benchmark.utils import BenchError
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.run.side_effect = RuntimeError('SSH unavailable')
        bench = CloudLabBench.__new__(CloudLabBench)
        bench.settings = SimpleNamespace(repo_name='test')
        bench._get_connection_kwargs = lambda host: {}
        bench.kill = Mock()
        with patch('benchmark.cloudlab_remote.Connection', return_value=connection):
            with self.assertRaises(BenchError):
                bench._release_benchmark([({'hostname': 'host'}, 'log', 'ready')])
        connection.put.assert_not_called()
        bench.kill.assert_called_once()
