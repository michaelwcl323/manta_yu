#!/usr/bin/env python3
"""
Script to run CloudLab benchmark and process logs
This script runs 'fab cloudlab_remote', downloads logs, and processes them
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path
from datetime import datetime

# Add benchmark directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from benchmark.logs import LogParser, ParseError, parse_primary_log_markers
from benchmark.utils import PathMaker, Print, BenchError

def run_fab_command(task='cloudlab_remote', debug=False, fab_kwargs=None):
    """Run fab command"""
    fab_cmd = ['fab', task]
    if debug:
        fab_cmd.append('debug=True')
    for key, value in (fab_kwargs or {}).items():
        fab_cmd.append(f'{key}={value}')
    
    Print.info(f'Running: {" ".join(fab_cmd)}')
    Print.info('=' * 60)
    
    try:
        result = subprocess.run(
            fab_cmd,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            check=False  # Don't raise on error, we'll check return code
        )
        return result.returncode == 0
    except FileNotFoundError:
        Print.error('fab command not found. Please install fabric:')
        Print.error('  pip install fabric')
        return False
    except Exception as e:
        Print.error(f'Failed to run fab command: {e}')
        return False

def download_logs_if_needed(settings_file='cloudlab_settings.json', max_workers=1, force_download=False):
    """Download logs if they don't exist locally"""
    logs_dir = Path(PathMaker.logs_path())
    
    # Check if logs already exist
    primary_logs = list(logs_dir.glob('primary-*.log'))
    worker_logs = list(logs_dir.glob('worker-*.log'))
    client_logs = list(logs_dir.glob('client-*.log'))
    
    if not force_download and (primary_logs or worker_logs or client_logs):
        Print.info(f'Found existing logs: {len(primary_logs)} primary, {len(worker_logs)} worker, {len(client_logs)} client')
        return True
    
    # Try to download logs
    if force_download:
        Print.info('Refreshing shared local logs from remote nodes...')
    else:
        Print.info('No local logs found, attempting to download from remote nodes...')
    try:
        from download_logs import download_logs
        return download_logs(settings_file, max_workers, refresh=force_download)
    except ImportError:
        Print.warn('download_logs.py not found, skipping download')
        return False

def process_logs(faults=0, save_to_file=True):
    """Process and display log results"""
    logs_dir = PathMaker.logs_path()
    
    if not os.path.exists(logs_dir):
        Print.error(f'Logs directory not found: {logs_dir}')
        return False
    
    Print.info('=' * 60)
    Print.info('Processing logs...')
    Print.info('=' * 60)
    
    try:
        parser = LogParser.process(logs_dir, faults=faults)
        result = parser.result()
        latency_csv = parser.export_latency_csv()

        # Derive attack-time alignment metadata so plotting scripts can place
        # attack markers on the same time axis as latency.csv.
        try:
            primary_boot_ts = min(parser.primary_boot_ts) if getattr(parser, 'primary_boot_ts', None) else None
            first_proposal_ts = min(parser.proposals.values()) if getattr(parser, 'proposals', None) else None
            boot_to_first_proposal_secs = (
                float(first_proposal_ts - primary_boot_ts)
                if (primary_boot_ts is not None and first_proposal_ts is not None)
                else None
            )
            primary0_markers = parse_primary_log_markers(PathMaker.primary_log_file(0))
            primary0_attack_start_ts = primary0_markers.get('attack_start_ts')
            primary0_attack_end_ts = primary0_markers.get('attack_end_ts')
            primary0_first_proposal_ts = primary0_markers.get('first_created_ts')

            current_metadata = PathMaker.load_run_metadata()
            configured_attack_start = (
                current_metadata.get('node_params', {}).get('attack_start_secs')
                if isinstance(current_metadata, dict)
                else None
            )
            configured_attack_duration = (
                current_metadata.get('node_params', {}).get('attack_duration_secs')
                if isinstance(current_metadata, dict)
                else None
            )
            attack_start_on_primary_axis = None
            if primary0_attack_start_ts is not None and first_proposal_ts is not None:
                attack_start_on_primary_axis = float(primary0_attack_start_ts - first_proposal_ts)
            elif configured_attack_start is not None and boot_to_first_proposal_secs is not None:
                attack_start_on_primary_axis = (
                    float(configured_attack_start) - boot_to_first_proposal_secs
                )

            attack_end_on_primary_axis = None
            if primary0_attack_end_ts is not None and first_proposal_ts is not None:
                attack_end_on_primary_axis = float(primary0_attack_end_ts - first_proposal_ts)

            attack_duration_from_logs = (
                float(primary0_attack_end_ts - primary0_attack_start_ts)
                if (
                    primary0_attack_start_ts is not None
                    and primary0_attack_end_ts is not None
                )
                else (
                    float(configured_attack_duration)
                    if configured_attack_duration is not None
                    else None
                )
            )

            PathMaker.update_run_metadata(
                {
                    'derived_timing': {
                        'primary_boot_ts': primary_boot_ts,
                        'first_proposal_ts': first_proposal_ts,
                        'primary_boot_to_first_proposal_secs': boot_to_first_proposal_secs,
                        'attack_start_on_primary_start_axis_secs': attack_start_on_primary_axis,
                        'attack_end_on_primary_start_axis_secs': attack_end_on_primary_axis,
                        'attack_duration_secs': attack_duration_from_logs,
                        'primary0_boot_ts': primary0_markers.get('boot_ts'),
                        'primary0_first_proposal_ts': primary0_first_proposal_ts,
                        'primary0_attack_start_ts': primary0_attack_start_ts,
                        'primary0_attack_end_ts': primary0_attack_end_ts,
                    }
                }
            )
        except Exception as timing_error:
            Print.warn(f'Failed to update derived timing metadata: {timing_error}')
        
        # Print results
        print(result)
        
        # Save to file
        if save_to_file:
            result_file = Path(PathMaker.summary_file())
            result_file.parent.mkdir(parents=True, exist_ok=True)

            with open(result_file, 'w') as f:
                f.write(f'Benchmark Results - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
                f.write('=' * 60 + '\n')
                f.write(result)
            
            Print.info(f'\nResults saved to: {result_file}')
            if latency_csv:
                Print.info(f'Latency CSV exported to: {latency_csv}')
        
        artifacts = PathMaker.export_run_artifacts()
        if 'final_dag' in artifacts:
            Print.info(f'Final DAG exported to: {artifacts["final_dag"]}')
        if 'solid_step_vertices_csv' in artifacts:
            Print.info(
                f'Solid-step CSV exported to: {artifacts["solid_step_vertices_csv"]}'
            )
        if 'dag_events_csv' in artifacts:
            Print.info(f'DAG events CSV exported to: {artifacts["dag_events_csv"]}')
        if 'dag_overview_html' in artifacts:
            Print.info(f'DAG overview HTML exported to: {artifacts["dag_overview_html"]}')
        
        return True
        
    except ParseError as e:
        Print.warn(f'Failed to parse logs: {e}')
        Print.warn('This may be because some log files are empty or incomplete.')
        return False
    except Exception as e:
        Print.warn(f'Error processing logs: {e}')
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Run CloudLab benchmark and process logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Run benchmark and process logs
  python3 run_cloudlab_benchmark.py

  # Only process existing logs (skip running benchmark)
  python3 run_cloudlab_benchmark.py --no-run

  # Run benchmark with debug mode
  python3 run_cloudlab_benchmark.py --debug

  # Only download logs without running benchmark
  python3 run_cloudlab_benchmark.py --download-only
        '''
    )
    
    parser.add_argument('--no-run', action='store_true',
                       help='Skip running fab cloudlab_remote, only process existing logs')
    parser.add_argument('--download-only', action='store_true',
                       help='Only download logs from remote nodes, do not run benchmark or process')
    parser.add_argument('--debug', action='store_true',
                       help='Run benchmark in debug mode')
    parser.add_argument('--faults', type=int, default=0,
                       help='Number of faulty nodes (default: 0)')
    parser.add_argument('--no-save', action='store_true',
                       help='Do not save results to file')
    parser.add_argument('--max-workers', type=int, default=1,
                       help='Maximum number of workers per node for log download (default: 1)')
    parser.add_argument('--settings', default='cloudlab_settings.json',
                       help='Path to CloudLab settings file (default: cloudlab_settings.json)')
    parser.add_argument('--sigma', type=int, default=2,
                       help='Sigma value for cloudlab_remote (default: 2)')
    parser.add_argument('--kappa', type=int, default=2,
                       help='Kappa value for cloudlab_remote (default: 2)')
    parser.add_argument('--reference', type=int, default=4,
                       help='Reference value for cloudlab_remote (default: 4)')
    parser.add_argument('--coverage', type=int, default=7,
                       help='Coverage value for cloudlab_remote (default: 7)')
    parser.add_argument('--allow-cross-step-weak-edges', dest='allow_cross_step_weak_edges',
                       action='store_true',
                       help='Enable weak edges that can cross solid-step boundaries within the same wave')
    parser.add_argument('--disable-cross-step-weak-edges', dest='allow_cross_step_weak_edges',
                       action='store_false',
                       help='Disable weak edges that cross solid-step boundaries; keep weak edges inside each solid step')
    parser.set_defaults(allow_cross_step_weak_edges=True)
    parser.add_argument('--fast-coin', dest='enable_fast_coin',
                       action='store_true',
                       help='Enable the fast-coin commit path that starts one round earlier than the regular check')
    parser.add_argument('--no-fast-coin', dest='enable_fast_coin',
                       action='store_false',
                       help='Disable the fast-coin commit path')
    parser.set_defaults(enable_fast_coin=False)
    parser.add_argument('--solid-commit-trigger-on-solid-step', dest='solid_commit_trigger_on_solid_step',
                       action='store_true',
                       help='Use the legacy solid-step trigger for the regular solid commit path instead of opening the check at the first vertex of the next solid wave')
    parser.add_argument('--no-solid-commit-trigger-on-solid-step', dest='solid_commit_trigger_on_solid_step',
                       action='store_false',
                       help='Open the regular solid commit check at the first vertex of the next solid wave (default)')
    parser.set_defaults(solid_commit_trigger_on_solid_step=False)
    parser.add_argument('--commit-recheck', dest='enable_commit_recheck',
                       action='store_true',
                       help='Enable repeated pending commit checks when late support certificates arrive')
    parser.add_argument('--no-commit-recheck', dest='enable_commit_recheck',
                       action='store_false',
                       help='Disable repeated pending commit checks for late support certificates')
    parser.set_defaults(enable_commit_recheck=True)
    parser.add_argument('--fast-coin-candidate-threshold', type=int, default=0,
                       help='Minimum number of leader-round vertices that must each gather f+1 support before fast coin starts leader selection')
    parser.add_argument('--solid-candidate-threshold', type=int, default=0,
                       help='Minimum number of leader-round vertices that must each gather f+1 support before the regular solid path starts leader selection')
    parser.add_argument('--adaptive-intermediate-spill', dest='enable_adaptive_intermediate_spill',
                       action='store_true',
                       help='Enable critical-first routing and spill a small amount of payload to the intermediate queue only after the critical backlog grows')
    parser.add_argument('--no-adaptive-intermediate-spill', dest='enable_adaptive_intermediate_spill',
                       action='store_false',
                       help='Disable adaptive spillover and keep the default queue behavior for the current worker setting')
    parser.set_defaults(enable_adaptive_intermediate_spill=False)
    parser.add_argument('--adaptive-intermediate-spill-trigger-digests', type=int, default=2,
                       help='Minimum number of critical-queue digests required before adaptive spill may route new digests to the intermediate queue')
    parser.add_argument('--adaptive-intermediate-spill-cap-digests', type=int, default=1,
                       help='Maximum number of digests to keep in the intermediate spill window before routing new digests back to the critical queue')
    parser.add_argument('--design-tag', default='manta',
                       help='Design tag written to summary and run directory name (default: manta)')
    parser.add_argument('--network-tag', default='default_network',
                       help='Network tag used in the output directory hierarchy and summary (default: default_network)')
    parser.add_argument('--load-tag', default='default_load',
                       help='Load tag used in the output directory hierarchy and summary (default: default_load)')
    parser.add_argument('--attack-enabled', dest='attack_enabled', action='store_true',
                       help='Enable the selective-broadcast attack')
    parser.add_argument('--no-attack', dest='attack_enabled', action='store_false',
                       help='Disable the selective-broadcast attack')
    parser.set_defaults(attack_enabled=False)
    parser.add_argument('--attack-start-secs', type=int, default=30,
                       help='Attack start time in seconds from run start')
    parser.add_argument('--attack-duration-secs', type=int, default=20,
                       help='Attack duration in seconds; 0 means keep attacking until the run ends')
    parser.add_argument('--attack-group-size', type=int, default=5,
                       help='Size of the first attack group; 0 splits nodes evenly')
    parser.add_argument('--attack-limit-headers', dest='attack_limit_headers', action='store_true',
                       help='Limit cross-group header broadcasts during the attack window')
    parser.add_argument('--no-attack-limit-headers', dest='attack_limit_headers', action='store_false',
                       help='Do not limit header broadcasts during the attack window')
    parser.set_defaults(attack_limit_headers=False)
    parser.add_argument('--attack-limit-certificates', dest='attack_limit_certificates', action='store_true',
                       help='Limit cross-group certificate broadcasts and sync replies during the attack window')
    parser.add_argument('--no-attack-limit-certificates', dest='attack_limit_certificates', action='store_false',
                       help='Do not limit certificate broadcasts during the attack window')
    parser.set_defaults(attack_limit_certificates=True)
    
    args = parser.parse_args()
    
    Print.heading('CloudLab Benchmark Runner')
    Print.info('=' * 60)
    
    success = True

    if args.no_run or args.download_only:
        current_run = PathMaker.current_run_path()
        if current_run:
            PathMaker.activate_run_directory(current_run)
        else:
            run_dir = PathMaker.create_run_directory(
                'cloudlab-manual',
                design_tag=args.design_tag,
                network_tag=args.network_tag,
                load_tag=args.load_tag,
            )
            Print.info(f'Run outputs directory: {run_dir}')
    
    # Step 1: Run benchmark (unless skipped)
    if not args.no_run and not args.download_only:
        success = run_fab_command(
            'cloudlab_remote',
            debug=args.debug,
            fab_kwargs={
                'sigma': args.sigma,
                'kappa': args.kappa,
                'reference': args.reference,
                'coverage': args.coverage,
                'allow_cross_step_weak_edges': args.allow_cross_step_weak_edges,
                'enable_fast_coin': args.enable_fast_coin,
                'solid_commit_trigger_on_solid_step': args.solid_commit_trigger_on_solid_step,
                'enable_commit_recheck': args.enable_commit_recheck,
                'fast_coin_candidate_threshold': args.fast_coin_candidate_threshold,
                'solid_candidate_threshold': args.solid_candidate_threshold,
                'enable_adaptive_intermediate_spill': args.enable_adaptive_intermediate_spill,
                'adaptive_intermediate_spill_trigger_digests': args.adaptive_intermediate_spill_trigger_digests,
                'adaptive_intermediate_spill_cap_digests': args.adaptive_intermediate_spill_cap_digests,
                'design_tag': args.design_tag,
                'network_tag': args.network_tag,
                'load_tag': args.load_tag,
                'attack_enabled': args.attack_enabled,
                'attack_start_secs': args.attack_start_secs,
                'attack_duration_secs': args.attack_duration_secs,
                'attack_group_size': args.attack_group_size,
                'attack_limit_headers': args.attack_limit_headers,
                'attack_limit_certificates': args.attack_limit_certificates,
            },
        )
        if not success:
            Print.warn('Benchmark run completed with errors, but continuing to process logs...')
        current_run = PathMaker.current_run_path()
        if current_run:
            PathMaker.activate_run_directory(current_run)
    
    # Step 2: Download logs if needed (unless download-only)
    if not args.download_only:
        download_logs_if_needed(
            args.settings,
            args.max_workers,
            force_download=not args.no_run,
        )
    else:
        # Download-only mode
        Print.info('Download-only mode: downloading logs from remote nodes...')
        download_logs_if_needed(args.settings, args.max_workers, force_download=True)
        Print.info('Download complete. Exiting.')
        return 0
    
    # Step 3: Process logs
    if not args.no_save:
        success = process_logs(faults=args.faults, save_to_file=True) and success
    else:
        success = process_logs(faults=args.faults, save_to_file=False) and success
    
    Print.info('=' * 60)
    if success:
        Print.info('✓ All operations completed successfully')
        return 0
    else:
        Print.warn('⚠ Some operations completed with errors')
        return 1

if __name__ == '__main__':
    sys.exit(main())
