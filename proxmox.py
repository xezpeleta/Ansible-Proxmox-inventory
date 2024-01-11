#!/usr/bin/env python3

# Copyright (C) 2014  Mathieu GAUTHIER-LAFAYE <gauthierl@lapth.cnrs.fr>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Updated 2016 by Matt Harris <matthaeus.harris@gmail.com>
#
# Added support for Proxmox VE 4.x
# Added support for using the Notes field of a VM to define groups and variables:
# A well-formatted JSON object in the Notes field will be added to the _meta
# section for that VM.  In addition, the "groups" key of this JSON object may be
# used to specify group membership:
#
# { "groups": ["utility", "databases"], "a": false, "b": true }

from six.moves.urllib import request, parse, error

try:
    import json
except ImportError:
    import simplejson as json
import os
import sys
import socket
import re
from optparse import OptionParser

from six import iteritems

from six.moves.urllib.error import HTTPError

from ansible.module_utils.urls import open_url


class ProxmoxNodeList(list):
    def get_names(self):
        return [node['node'] for node in self]


class ProxmoxVM(dict):
    def get_variables(self):
        variables = {}
        for key, value in iteritems(self):
            variables['proxmox_' + key] = value
        return variables


class ProxmoxVMList(list):
    def __init__(self, data=[], pxmxver=0.0):
        self.ver = pxmxver
        for item in data:
            self.append(ProxmoxVM(item))

    def get_names(self):
        if self.ver >= 4.0:
            return [vm['name'] for vm in self if 'template' in vm and vm['template'] != 1]
        else:
            return [vm['name'] for vm in self]

    def get_by_name(self, name):
        results = [vm for vm in self if vm['name'] == name]
        return results[0] if len(results) > 0 else None

    def get_variables(self):
        variables = {}
        for vm in self:
            variables[vm['name']] = vm.get_variables()

        return variables


class ProxmoxPoolList(list):
    def get_names(self):
        return [pool['poolid'] for pool in self]


class ProxmoxVersion(dict):
    def get_version(self):
        return float(self['version'].split('.')[0])


class ProxmoxPool(dict):
    def get_members_name(self):
        return [member['name'] for member in self['members'] if (member['type'] == 'qemu' or member['type'] == 'lxc') and member['template'] != 1]


class ProxmoxAPI(object):
    def __init__(self, options, config_path):
        self.options = options
        self.credentials = None

        if not options.url or not options.username or not options.password:
            if os.path.isfile(config_path):
                with open(config_path, "r") as config_file:
                    config_data = json.load(config_file)
                    if not options.url:
                        try:
                            options.url = config_data["url"]
                        except KeyError:
                            options.url = None
                    if not options.username:
                        try:
                            options.username = config_data["username"]
                        except KeyError:
                            options.username = None
                    if not options.password:
                        try:
                            options.password = config_data["password"]
                        except KeyError:
                            options.password = None
                    if not options.token:
                        try:
                            options.token = config_data["token"]
                        except KeyError:
                            options.token = None
                    if not options.secret:
                        try:
                            options.secret = config_data["secret"]
                        except KeyError:
                            options.secret = None
                    if not options.include:
                        options.include = config_data["include"]
                    if not options.exclude:
                        options.exclude = config_data["exclude"]

        if not options.url:
            raise Exception('Missing mandatory parameter --url (or PROXMOX_URL or "url" key in config file).')
        elif not options.username:
            raise Exception(
                'Missing mandatory parameter --username (or PROXMOX_USERNAME or "username" key in config file).')
        elif not options.password and (not options.token or not options.secret):
            raise Exception(
                'Missing mandatory parameter --password (or PROXMOX_PASSWORD or "password" key in config file) or alternatively --token and --secret (or PROXMOX_TOKEN and PROXMOX_SECRET or "token" and "secret" key in config file).')

        # URL should end with a trailing slash
        if not options.url.endswith("/"):
            options.url = options.url + "/"

    def auth(self):
        if not self.options.token or not self.options.secret:
            request_path = '{0}api2/json/access/ticket'.format(self.options.url)

            request_params = parse.urlencode({
                'username': self.options.username,
                'password': self.options.password,
            })

            data = json.load(open_url(request_path, data=request_params,
                                    validate_certs=self.options.validate))

            self.credentials = {
                'ticket': data['data']['ticket'],
                'CSRFPreventionToken': data['data']['CSRFPreventionToken'],
            }

    def get(self, url, data=None):
        request_path = '{0}{1}'.format(self.options.url, url)

        headers = {}
        if not self.options.token or not self.options.secret:
            headers['Cookie'] = 'PVEAuthCookie={0}'.format(self.credentials['ticket'])
        else:
            headers['Authorization'] = 'PVEAPIToken={0}!{1}={2}'.format(self.options.username, self.options.token, self.options.secret)
        
        request = open_url(request_path, data=data, headers=headers,
                           validate_certs=self.options.validate)

        response = json.load(request)
        return response['data']

    def nodes(self):
        return ProxmoxNodeList(self.get('api2/json/nodes'))

    def vms_by_type(self, node, type):
        return ProxmoxVMList(self.get('api2/json/nodes/{0}/{1}'.format(node, type)), self.version().get_version())

    def vm_description_by_type(self, node, vm, type):
        return self.get('api2/json/nodes/{0}/{1}/{2}/config'.format(node, type, vm))

    def node_qemu(self, node):
        return self.vms_by_type(node, 'qemu')

    def node_qemu_description(self, node, vm):
        return self.vm_description_by_type(node, vm, 'qemu')

    def node_lxc(self, node):
        return self.vms_by_type(node, 'lxc')

    def node_lxc_description(self, node, vm):
        return self.vm_description_by_type(node, vm, 'lxc')

    def node_openvz(self, node):
        return self.vms_by_type(node, 'openvz')

    def node_openvz_description(self, node, vm):
        return self.vm_description_by_type(node, vm, 'openvz')

    def pools(self):
        return ProxmoxPoolList(self.get('api2/json/pools'))

    def pool(self, poolid):
        return ProxmoxPool(self.get('api2/json/pools/{0}'.format(poolid)))
    
    def qemu_agent(self, node, vm):
        try:
            info = self.get('api2/json/nodes/{0}/qemu/{1}/agent/info'.format(node, vm))
            if info is not None:
                return True
        except HTTPError as error:
            return False

    def openvz_ip_address(self, node, vm):
        try:
            config = self.get('api2/json/nodes/{0}/lxc/{1}/config'.format(node, vm))
        except HTTPError:
            return False
        
        try:
            ip_address = re.search('ip=(\d*\.\d*\.\d*\.\d*)', config['net0']).group(1)
            return ip_address
        except:
            return False

### PATCH for LXC HOSTNAME 
### GET HOSTNAME for LXC-Containers

    def lxc_hostname(self, node, vm):
        try:
            config = self.get('api2/json/nodes/{0}/lxc/{1}/config'.format(node, vm))
        except HTTPError:
            return False
        
        try:
            hostname = config['hostname']
            return hostname
        except:
            return False
    
    def version(self):
        return ProxmoxVersion(self.get('api2/json/version'))

    def qemu_agent_info(self, node, vm):
        system_info = SystemInfo()
        osinfo = self.get('api2/json/nodes/{0}/qemu/{1}/agent/get-osinfo'.format(node, vm))['result']
        if osinfo:
            if 'id' in osinfo:
                system_info.id = osinfo['id']

            if 'name' in osinfo:
                system_info.name = osinfo['name']

            if 'machine' in osinfo:
                system_info.machine = osinfo['machine']

            if 'kernel-release' in osinfo:
                system_info.kernel = osinfo['kernel-release']

            if 'version-id' in osinfo:
                system_info.version_id = osinfo['version-id']

        ip_address = None
        networks = self.get('api2/json/nodes/{0}/qemu/{1}/agent/network-get-interfaces'.format(node, vm))['result']
        
        if networks:
            if type(networks) is dict:
                for network in networks:
                    if self.valid_network_interface(network):
                        for ip_address in network['ip-address']:
                            try:
                                # IP address validation
                                if ip_address['ip-address'] != '127.0.0.1' and socket.inet_aton(ip_address['ip-address']):
                                    system_info.ip_address = ip_address
                            except socket.error:
                                pass
            elif type(networks) is list:
                for network in networks:
                    if self.valid_network_interface(network):
                        for ip_address in network['ip-addresses']:
                            try:
                                if ip_address['ip-address'] != '127.0.0.1' and socket.inet_aton(ip_address['ip-address']):
                                    system_info.ip_address = ip_address['ip-address']
                            except socket.error:
                                pass

        return system_info

    def valid_network_interface(self, network):
        if 'ip-addresses' not in network:
            return False
        
        # Include/Exclude are mutally exclusive
        if len(self.options.include) > 0:
            for regex in self.options.include:
                if re.match(regex, network["name"]):
                    return True
            return False
        
        if len(self.options.exclude) > 0:
            for regex in self.options.exclude:
                if re.match(regex, network["name"]):
                    return False
            return True
        
        return True

class SystemInfo(object):
    id = ""
    name = ""
    machine = ""
    kernel = ""
    version_id = ""
    ip_address = ""


def main_list(options, config_path):
    results = {
        'all': {
            'hosts': [],
        },
        '_meta': {
            'hostvars': {},
        }
    }

    proxmox_api = ProxmoxAPI(options, config_path)
    proxmox_api.auth()

    for node in proxmox_api.nodes().get_names():
        try:
            qemu_list = proxmox_api.node_qemu(node)
        except HTTPError as error:
            # the API raises code 595 when target node is unavailable, skip it
            if error.code == 595 or error.code == 596:
                continue
            # if it was some other error, reraise it
            raise error
        results['all']['hosts'] += qemu_list.get_names()
        results['_meta']['hostvars'].update(qemu_list.get_variables())
        if proxmox_api.version().get_version() >= 4.0:
            lxc_list = proxmox_api.node_lxc(node)
            results['all']['hosts'] += lxc_list.get_names()
            results['_meta']['hostvars'].update(lxc_list.get_variables())
        else:
            openvz_list = proxmox_api.node_openvz(node)
            results['all']['hosts'] += openvz_list.get_names()
            results['_meta']['hostvars'].update(openvz_list.get_variables())

        # Merge QEMU and Containers lists from this node
        node_hostvars = qemu_list.get_variables().copy()
        if proxmox_api.version().get_version() >= 4.0:
            node_hostvars.update(lxc_list.get_variables())
        else:
            node_hostvars.update(openvz_list.get_variables())

        # Check only VM/containers from the current node
        for vm in node_hostvars:
            vmid = results['_meta']['hostvars'][vm]['proxmox_vmid']
            try:
                type = results['_meta']['hostvars'][vm]['proxmox_type']
            except KeyError:
                type = 'qemu'
                results['_meta']['hostvars'][vm]['proxmox_type'] = 'qemu'
            try:
                description = proxmox_api.vm_description_by_type(node, vmid, type)['description']
            except KeyError:
                description = None

            try:
                metadata = json.loads(description)
            except TypeError:
                metadata = {}
            except ValueError:
                metadata = {
                    'notes': description
                }
            
            if type == 'qemu':
                # Retrieve information from QEMU agent if installed
                if proxmox_api.qemu_agent(node, vmid):
                    system_info = proxmox_api.qemu_agent_info(node, vmid)
                    results['_meta']['hostvars'][vm]['ansible_host'] = system_info.ip_address
                    results['_meta']['hostvars'][vm]['proxmox_os_id'] = system_info.id
                    results['_meta']['hostvars'][vm]['proxmox_os_name'] = system_info.name
                    results['_meta']['hostvars'][vm]['proxmox_os_machine'] = system_info.machine
                    results['_meta']['hostvars'][vm]['proxmox_os_kernel'] = system_info.kernel
                    results['_meta']['hostvars'][vm]['proxmox_os_version_id'] = system_info.version_id
            else:
             # IF IP is empty (due DHCP, take hostname instead)
                if proxmox_api.openvz_ip_address(node, vm) != False:
                    results['_meta']['hostvars'][vm]['ansible_host'] = proxmox_api.openvz_ip_address(node, vmid)
                else:
                    results['_meta']['hostvars'][vm]['ansible_host'] = proxmox_api.lxc_hostname(node, vmid)

            if 'groups' in metadata:
                # print metadata
                for group in metadata['groups']:
                    if group not in results:
                        results[group] = {
                            'hosts': []
                        }
                    results[group]['hosts'] += [vm]

            # Create group 'running'
            # so you can: --limit 'running'
            status = results['_meta']['hostvars'][vm]['proxmox_status']
            if status == 'running':
                if 'running' not in results:
                    results['running'] = {
                        'hosts': []
                    }
                results['running']['hosts'] += [vm]

            if 'proxmox_os_id' in results['_meta']['hostvars'][vm]:
                osid = results['_meta']['hostvars'][vm]['proxmox_os_id']
                if osid:
                    if osid not in results:
                        results[osid] = {
                            'hosts': []
                        }
                    results[osid]['hosts'] += [vm]

            # Create group 'based on proxmox_tags'
            # so you can: --limit 'worker,external-datastore'
            try:
                tags = results['_meta']['hostvars'][vm]['proxmox_tags']
                vm_name = results['_meta']['hostvars'][vm]['proxmox_name']
                tag_list = split_tags(tags)
                for i in range(len(tag_list)):
                    if tag_list[i] not in results:
                        results[tag_list[i]] = {
                            'hosts': []
                        }
                    results[tag_list[i]]['hosts'] += [vm]
            except KeyError:
                pass
           
            results['_meta']['hostvars'][vm].update(metadata)

    # pools
    for pool in proxmox_api.pools().get_names():
        results[pool] = {
            'hosts': proxmox_api.pool(pool).get_members_name(),
        }
    return results

def split_tags(proxmox_tags: str) -> list[str]:
    """
    Splits proxmox_tags delimited by comma and returns a list of the tags.
    """
    tags = proxmox_tags.split(';')
    return tags

def main_host(options, config_path):
    proxmox_api = ProxmoxAPI(options, config_path)
    proxmox_api.auth()

    for node in proxmox_api.nodes().get_names():
        qemu_list = proxmox_api.node_qemu(node)
        qemu = qemu_list.get_by_name(options.host)
        if qemu:
            return qemu.get_variables()

    return {}


def main():
    config_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        os.path.splitext(os.path.basename(__file__))[0] + ".json"
    )

    bool_validate_cert = True
    if os.path.isfile(config_path):
        with open(config_path, "r") as config_file:
            config_data = json.load(config_file)
            try:
                bool_validate_cert = config_data["validateCert"]
            except KeyError:
                pass
    if 'PROXMOX_INVALID_CERT' in os.environ:
        bool_validate_cert = False

    parser = OptionParser(usage='%prog [options] --list | --host HOSTNAME')
    parser.add_option('--list', action="store_true", default=False, dest="list")
    parser.add_option('--host', dest="host")
    parser.add_option('--url', default=os.environ.get('PROXMOX_URL'), dest='url')
    parser.add_option('--username', default=os.environ.get('PROXMOX_USERNAME'), dest='username')
    parser.add_option('--password', default=os.environ.get('PROXMOX_PASSWORD'), dest='password')
    parser.add_option('--token', default=os.environ.get('PROXMOX_TOKEN'), dest='token')
    parser.add_option('--secret', default=os.environ.get('PROXMOX_SECRET'), dest='secret')
    parser.add_option('--pretty', action="store_true", default=False, dest='pretty')
    parser.add_option('--trust-invalid-certs', action="store_false", default=bool_validate_cert, dest='validate')
    parser.add_option('--include', default=os.environ.get("INCLUDE_FILTER", []), action="append")
    parser.add_option('--exclude', default=os.environ.get("EXCLUDE_FILTER", []), action="append")
    (options, args) = parser.parse_args()

    if type(options.list) is str:
        options.list = options.list.split(";")

    if options.list:
        data = main_list(options, config_path)
    elif options.host:
        data = main_host(options, config_path)
    else:
        parser.print_help()
        sys.exit(1)

    indent = None
    if options.pretty:
        indent = 2
#TODO
    print((json.dumps(data, indent=indent)))


if __name__ == '__main__':
    main()
