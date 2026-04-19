# Copyright(C) Facebook, Inc. and its affiliates.
from fabric import task

from benchmark.local import LocalBench
from benchmark.logs import ParseError, LogParser
from benchmark.utils import Print, PathMaker
from benchmark.cloudlab_instance import CloudLabInstanceManager
from benchmark.cloudlab_remote import CloudLabBench
from benchmark.cloudlab_wan import CloudLabWan
from benchmark.utils import BenchError

def _coerce_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')

# Import AWS remote benchmark module only when needed (lazy import).
try:
    from benchmark.remote import Bench
except ImportError:
    Bench = None

# Import AWS instance module only when needed (lazy import - CloudLab doesn't need it)
try:
    from benchmark.instance import InstanceManager
except ImportError:
    InstanceManager = None

# Import plot module only when needed (lazy import)
try:
    from benchmark.plot import Ploter, PlotError
except ImportError:
    Ploter = None
    PlotError = None


@task
def local(ctx, debug=False):
    ''' Run benchmarks on localhost '''
    bench_params = {
        'faults': 0,
        'nodes': 10,
        'workers': 1,
        'rate_type': 'balanced',
        'rate': 80000,
        'tx_size': 512,
        'duration': 20,
    }
    node_params = {
        'header_size': 1000,  # bytes
        'max_header_delay': 200,  # ms
        'gc_depth': 50,  # rounds
        'sync_retry_delay': 1000,  # ms
        'sync_retry_nodes': 7,  # number of nodes
        'batch_size': 500_000,  # bytes
        'max_batch_delay': 200,  # ms
        'sigma': 2,
        'kappa': 2,
        'reference': 4,
        'coverage': 7,
        'allow_cross_step_weak_edges': True,
        'enable_fast_coin': False,
        'solid_commit_trigger_on_solid_step': False,
        'fast_coin_candidate_threshold': 0,
        'solid_candidate_threshold': 0,
        's': 0.99
    }
    try:
        ret = LocalBench(bench_params, node_params).run(debug)
        print(ret.result())
    except BenchError as e:
        Print.error(e)


@task
def create(ctx, nodes=2):
    ''' Create a testbed'''
    if InstanceManager is None:
        Print.error('InstanceManager is not available (boto3 may not be installed)')
        return
    try:
        InstanceManager.make().create_instances(nodes)
    except BenchError as e:
        Print.error(e)


@task
def destroy(ctx):
    ''' Destroy the testbed '''
    if InstanceManager is None:
        Print.error('InstanceManager is not available (boto3 may not be installed)')
        return
    try:
        InstanceManager.make().terminate_instances()
    except BenchError as e:
        Print.error(e)


@task
def start(ctx, max=2):
    ''' Start at most `max` machines per data center '''
    if InstanceManager is None:
        Print.error('InstanceManager is not available (boto3 may not be installed)')
        return
    try:
        InstanceManager.make().start_instances(max)
    except BenchError as e:
        Print.error(e)


@task
def stop(ctx):
    ''' Stop all machines '''
    if InstanceManager is None:
        Print.error('InstanceManager is not available (boto3 may not be installed)')
        return
    try:
        InstanceManager.make().stop_instances()
    except BenchError as e:
        Print.error(e)


@task
def info(ctx):
    ''' Display connect information about all the available machines (AWS) '''
    if InstanceManager is None:
        Print.error('InstanceManager is not available (boto3 may not be installed)')
        return
    try:
        InstanceManager.make().print_info()
    except BenchError as e:
        Print.error(e)


@task
def install(ctx):
    ''' Install the codebase on all machines '''
    if Bench is None:
        Print.error('AWS benchmark support is not available (remote dependencies may not be installed)')
        return
    try:
        Bench(ctx).install()
    except BenchError as e:
        Print.error(e)


@task
def remote(ctx, debug=False):
    ''' Run benchmarks on AWS '''
    if Bench is None:
        Print.error('AWS benchmark support is not available (remote dependencies may not be installed)')
        return
    bench_params = {
        'faults': 3,
        'nodes': [10],
        'workers': 1,
        'collocate': True,
        'rate': [10_000, 110_000],
        'tx_size': 512,
        'duration': 300,
        'runs': 2,
    }
    node_params = {
        'header_size': 1_000,  # bytes
        'max_header_delay': 200,  # ms
        'gc_depth': 50,  # rounds
        'sync_retry_delay': 10_000,  # ms
        'sync_retry_nodes': 3,  # number of nodes
        'batch_size': 500_000,  # bytes
        'max_batch_delay': 200,  # ms
        'solid_step_length': 2,
        'solid_step_number': 1,
        'reference': 3,
    }
    try:
        Bench(ctx).run(bench_params, node_params, debug)
    except BenchError as e:
        Print.error(e)


@task
def plot(ctx):
    ''' Plot performance using the logs generated by "fab remote" '''
    if Ploter is None:
        Print.error('matplotlib is not installed. Please install it: pip install matplotlib')
        return
    plot_params = {
        'faults': [0],
        'nodes': [10, 20, 50],
        'workers': [1],
        'collocate': True,
        'tx_size': 512,
        'max_latency': [3_500, 4_500]
    }
    try:
        Ploter.plot(plot_params)
    except PlotError as e:
        Print.error(BenchError('Failed to plot performance', e))


@task
def kill(ctx):
    ''' Stop execution on all machines (AWS) '''
    if Bench is None:
        Print.error('AWS benchmark support is not available (remote dependencies may not be installed)')
        return
    try:
        Bench(ctx).kill()
    except BenchError as e:
        Print.error(e)


@task
def logs(ctx):
    ''' Print a summary of the logs '''
    try:
        print(LogParser.process(PathMaker.logs_path(), faults='?').result())
    except ParseError as e:
        Print.error(BenchError('Failed to parse logs', e))


# CloudLab tasks (same as experiment1 / experiment2)
@task
def cloudlab_info(ctx):
    ''' Display connect information about all CloudLab nodes '''
    try:
        CloudLabInstanceManager.make().print_info()
    except BenchError as e:
        Print.error(e)


@task
def cloudlab_test(ctx):
    ''' Test SSH connections to all CloudLab nodes '''
    try:
        CloudLabBench(ctx).test_connections()
    except BenchError as e:
        Print.error(e)


@task
def cloudlab_install(ctx):
    ''' Install the codebase on all CloudLab nodes '''
    try:
        CloudLabBench(ctx).install()
    except BenchError as e:
        Print.error(e)

@task
def cloudlab_wan(ctx, action='setup', settings_file='cloudlab_settings.json'):
    ''' Emulate WAN RTT between sites (tc netem). action=setup|clear. Optional settings_file=... '''
    try:
        w = CloudLabWan(settings_file=settings_file)
        act = (action or 'setup').lower()
        if act == 'setup':
            w.setup()
        elif act == 'clear':
            w.clear()
        else:
            Print.error('cloudlab_wan: use action=setup or action=clear')
    except BenchError as e:
        Print.error(e)

@task
def cloudlab_remote(
    ctx,
    debug=False,
    sigma=1,
    kappa=2,
    reference=7,
    coverage=7,


    allow_cross_step_weak_edges=False,  # 跨solid-step的weak edges

# 提交规则：
#     对同一个 r1 leader，有 3 次机会：
# 1. Fast coin 提前机会
#    - 触发时机：收到第一个 r3 顶点
#    - 检查对象：r2 -> r1
#    - 额外前提：已经看到足够的候选顶点
# 2. Solid-step 提前机会
#    - 触发时机：收到第一个 r4 顶点
#    - 检查对象：r3 -> r1
#    - 额外前提：已经看到足够的候选顶点
# 3. 默认 regular 路径
#    - 触发时机：收到第一个 r5 顶点
#    - 检查对象：r3 -> r1
#    - 只要前面没提交成功，就还要走这一步

    enable_fast_coin=False, # 关闭提前提交路径，保留 regular solid path
    solid_commit_trigger_on_solid_step=False,
    enable_commit_recheck=False,
    fast_coin_candidate_threshold=0,
    solid_candidate_threshold=0,

    attack_enabled=True,
    attack_start_secs=60,
    attack_duration_secs=1000,
    attack_group_size=5,
    attack_limit_headers=False,
    attack_limit_certificates=True,

    # 这是payload 的调度，第三轮和第二轮的顶点接收payload，目前以第三轮顶点优先，多余的给第二轮
    enable_adaptive_intermediate_spill=False, # payload shceduling
    adaptive_intermediate_spill_trigger_digests=2,
    adaptive_intermediate_spill_cap_digests=1,

    #会根据这些tag会自动生成目录，将运行结果分类 目录是 design_tag/network_tag/load_tag/
    design_tag='experiment2_attack_final',
    network_tag='geo',
    load_tag='balanced_50_500000_50',
):
    ''' Run benchmarks on CloudLab '''
    allow_cross_step_weak_edges = _coerce_bool(allow_cross_step_weak_edges)
    enable_fast_coin = _coerce_bool(enable_fast_coin)
    solid_commit_trigger_on_solid_step = _coerce_bool(solid_commit_trigger_on_solid_step)
    enable_commit_recheck = _coerce_bool(enable_commit_recheck)
    attack_enabled = _coerce_bool(attack_enabled)
    attack_limit_headers = _coerce_bool(attack_limit_headers)
    attack_limit_certificates = _coerce_bool(attack_limit_certificates)
    enable_adaptive_intermediate_spill = _coerce_bool(enable_adaptive_intermediate_spill)
    bench_params = {
        'faults': 0,
        'nodes': [10],
        'workers': 1,
        'collocate': True,
        'rate_type': 'balanced',
        'rate': [100000],
        # 'rate': [40000,60000],
        # 'rate': [40000,80000,100000,120000,140000,150000,160000,180000],
        # 'rate': [130000],
        'tx_size': 512,
        'duration': 120,
        'runs': 1,       
    }

    # manta 对以下参数比较敏感 可调整成 50/500_000/50   100/500_000/100  50/128_000/50 80/128_000/35 等等
    # 下面这组在geo631表现还可以, 有时候跑的不稳，900左右是正常，如果超过1000了可能是波动或者这个参数没有调优
    #  'max_header_delay': 80,  # ms
    #  'batch_size': 500_000,  # bytes
    # 'max_batch_delay': 35,  # ms
    node_params = {
        'header_size': 1_000,  # bytes
        'max_header_delay': 50,  # ms
        'gc_depth': 200,  # rounds
        'sync_retry_delay': 1000,  # ms
        'sync_retry_nodes': 7,  # number of nodes
        'batch_size': 500000,  # bytes
        'max_batch_delay': 50,  # ms
        'sigma': sigma,
        'kappa': kappa,
        'reference': reference,
        'coverage': coverage,
        'allow_cross_step_weak_edges': allow_cross_step_weak_edges,
        'enable_fast_coin': enable_fast_coin,
        'solid_commit_trigger_on_solid_step': solid_commit_trigger_on_solid_step,
        'enable_commit_recheck': enable_commit_recheck,
        'fast_coin_candidate_threshold': int(fast_coin_candidate_threshold),
        'solid_candidate_threshold': int(solid_candidate_threshold),
        'attack_enabled': attack_enabled,
        'attack_start_secs': int(attack_start_secs),
        'attack_duration_secs': int(attack_duration_secs),
        'attack_group_size': int(attack_group_size),
        'attack_limit_headers': attack_limit_headers,
        'attack_limit_certificates': attack_limit_certificates,
        'enable_adaptive_intermediate_spill': enable_adaptive_intermediate_spill,
        'adaptive_intermediate_spill_trigger_digests': int(adaptive_intermediate_spill_trigger_digests),
        'adaptive_intermediate_spill_cap_digests': int(adaptive_intermediate_spill_cap_digests),
        'design_tag': design_tag,
        'network_tag': network_tag,
        'load_tag': load_tag,
        # 's': 0.99,
    }
    try:
        CloudLabBench(ctx).run(bench_params, node_params, debug)
    except BenchError as e:
        Print.error(e)


@task
def cloudlab_status(ctx):
    ''' Check if benchmark processes are running on CloudLab nodes '''
    try:
        CloudLabBench(ctx).status()
    except BenchError as e:
        Print.error(e)


@task
def cloudlab_debug(ctx):
    ''' Debug: Check tmux sessions and capture error messages from CloudLab nodes '''
    try:
        CloudLabBench(ctx).debug_sessions()
    except BenchError as e:
        Print.error(e)


@task
def cloudlab_kill(ctx):
    ''' Stop execution on all CloudLab nodes '''
    try:
        CloudLabBench(ctx).kill()
    except BenchError as e:
        Print.error(e)


@task
def cloudlab_download_primary_logs(ctx, nodes='0,1,2,3'):
    ''' Download primary logs from specified CloudLab nodes (default: 0,1,2,3) '''
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from download_logs import download_primary_logs

    try:
        node_indices = [int(x.strip()) for x in nodes.split(',')]
        Print.info(f'Downloading primary logs from nodes: {node_indices}')
        success = download_primary_logs('cloudlab_settings.json', node_indices)
        if success:
            Print.info('✓ Successfully downloaded primary logs')
        else:
            Print.error('✗ Failed to download some primary logs')
        return success
    except ValueError as e:
        Print.error(f'Invalid node indices format: {nodes}. Use comma-separated numbers like "0,1,2,3"')
        return False
    except Exception as e:
        Print.error(f'Failed to download primary logs: {e}')
        return False
