# Copyright(C) Facebook, Inc. and its affiliates.
import ipaddress
from collections import OrderedDict
from json import load, JSONDecodeError


class SettingsError(Exception):
    pass


def _validate_ip(s):
    s = str(s).strip()
    if not s:
        raise SettingsError('Empty IP in hosts list')
    try:
        ipaddress.ip_address(s)
    except ValueError as e:
        raise SettingsError(f'Invalid IP address: {s!r}') from e
    return s


class Settings:
    def __init__(self, key_name, key_path, base_port, repo_name, repo_url,
                 branch, instance_type, aws_regions,
                 static_hosts_by_region=None):
        inputs_str = [
            key_name, key_path, repo_name, repo_url, branch, instance_type
        ]
        if isinstance(aws_regions, list):
            regions = aws_regions
        else:
            regions = [aws_regions]
        inputs_str += regions
        ok = all(isinstance(x, str) for x in inputs_str)
        ok &= isinstance(base_port, int)
        ok &= len(regions) > 0
        if not ok:
            raise SettingsError('Invalid settings types')

        self.key_name = key_name
        self.key_path = key_path

        self.base_port = base_port

        self.repo_name = repo_name
        self.repo_url = repo_url
        self.branch = branch

        self.instance_type = instance_type
        self.aws_regions = regions
        self.static_hosts_by_region = static_hosts_by_region or OrderedDict()

    @classmethod
    def load(cls, filename):
        try:
            with open(filename, 'r') as f:
                data = load(f)

            static_hosts_by_region = cls._parse_hosts_field(data.get('hosts'))

            return cls(
                data['key']['name'],
                data['key']['path'],
                data['port'],
                data['repo']['name'],
                data['repo']['url'],
                data['repo']['branch'],
                data['instances']['type'],
                data['instances']['regions'],
                static_hosts_by_region,
            )
        except (OSError, JSONDecodeError) as e:
            raise SettingsError(str(e))

        except KeyError as e:
            raise SettingsError(f'Malformed settings: missing key {e}')

    @staticmethod
    def _parse_hosts_field(raw):
        '''Build region -> [ip] from settings "hosts".

        Supported shapes:
        - ["10.0.0.1", "10.0.0.2", ...]  — only IPs, single group `static`
        - {"ap-east-1": ["10.0.0.1", ...], ...}  — IPs grouped by region name
        - [{"region": "r", "ips": ["10.0.0.1", ...]}, ...]  — legacy list form
        '''
        if raw is None:
            return OrderedDict()
        out = OrderedDict()

        if isinstance(raw, list):
            if len(raw) == 0:
                return out
            if isinstance(raw[0], str):
                ips = [_validate_ip(x) for x in raw]
                out['static'] = ips
                return out
            if isinstance(raw[0], dict):
                for entry in raw:
                    if 'ips' in entry:
                        region = entry['region']
                        ips = [_validate_ip(x) for x in entry['ips']]
                    elif 'range' in entry:
                        raise SettingsError(
                            'Host "range" is no longer supported; use a list of IP strings only.'
                        )
                    else:
                        raise SettingsError(
                            'Each hosts[] item must include "region" and "ips" (list of IP strings).'
                        )
                    out[region] = ips
                return out
            raise SettingsError('hosts[] must be a list of IP strings, or list of {region, ips} objects.')

        if isinstance(raw, dict):
            for region, ips in raw.items():
                if not isinstance(ips, list):
                    raise SettingsError(
                        f'hosts.{region} must be a list of IP strings.'
                    )
                out[region] = [_validate_ip(x) for x in ips]
            return out

        raise SettingsError('hosts must be a list of IPs, a list of {region, ips}, or an object of region -> ips.')
