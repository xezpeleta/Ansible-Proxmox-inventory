# Ansible-Proxmox-inventory

## About

Proxmox dynamic inventory for Ansible. Based on [original plugin](https://raw.githubusercontent.com/ansible/ansible/devel/contrib/inventory/proxmox.py) from Mathieu Gauthier-Lafaye

### How does it work?

It will generate an inventory on the fly with all your VMs stored in your ProxmoxVE. Therefore, Ansible will be able to connect to all your VM.

### Requirements

Resolvable VM names: the inventory script collects the VM names (and not IP addresses!). That's why your computer must be able to resolve these names; either with the DNS server or your */etc/hosts* 


### Features

- **ProxmoxVE cluster**: if your have a ProxmoxVE cluster, it will gather the whole VM list from your cluster
- **Advanced filtering**: you can filter the VM list based in their status or a custom tag included in the `Notes` field


### Changelog:
- Added option to ignore invalid SSL certificate (by @bmillemathias) [PR](https://github.com/ansible/ansible/pull/17247)
- Compatible with a Proxmox cluster (by @xezpeleta)
- Added group 'running' (by @xezpeleta)
- Added backwards compatibility with openvz and Proxmox3 (@isindir) [#1]
- Added optional JSON configuration file (@nmaggioni) [#2]
- Added backwards compatibility with python 2.6 (@isindir) [#3]
- Handle cases where node is unavailable (@andor44) [#7]
- Fix python 2 and 3 compatibility (@gardar) [#14]
- Filter on qemu and lxc resources only (@adubreuiltk) [#16]
- Get the IP address automatically (@xezpeleta) [#8]

## Instructions

Download **proxmox.py** to */etc/ansible/* directory:

```sh
cd /etc/ansible
sudo wget https://github.com/xezpeleta/Ansible-Proxmox-inventory/raw/master/proxmox.py
sudo chmod +x proxmox.py
```

Let's test it:

```sh
python /etc/ansible/proxmox.py \
  --url=https://<your-proxmox-url>:8006/ \
  --username=<proxmox-username> \
  --password=<proxmox-password> \
  --trust-invalid-certs \
  --list --pretty
```

If you get a list with all the VM in your Proxmox cluster, everything is ok.

I suggest you to use environment variables to store Proxmox credentials:

```sh
# You also can do that using the file setenv.sh
# Run the command: "source setenv.sh"
export PROXMOX_URL=https://10.0.0.1:8006/
export PROXMOX_USERNAME=apiuser@pve
export PROXMOX_PASSWORD=apiuser1234
export PROXMOX_INVALID_CERT=False
```

You may also save your settings in a JSON file with the same name of the Python script, in its same folder (e.g.: if the downloaded script is `/etc/ansible/proxmox.py`, the configuration file will be `/etc/ansible/proxmox.json`): 

```json
{
    "url": "https://10.0.0.1:8006/",
    "username": "apiuser@pve",
    "password": "apiuser1234",
    "validateCert": false
}
```

So now you can check it again without credential parameters:

```sh
python /etc/ansible/proxmox.py --list --pretty
```

Once you get this working, you can include the dynamic inventory in your ansible commands:

```sh
# Ping: connect to all VM in Proxmox using root user
ansible -i /etc/ansible/proxmox.py all -m ping -u root
```

## Tricks

If you prefer, you can limit the commands to the group "running":

```sh
# Run a playbook in every running VM in Proxmox
ansible-playbook -i /etc/ansible/proxmox.py --limit='running' playbook-example/playbook.yml
```

Thanks to Matt Harris, you can now use the Notes field in Proxmox to add a host to a group:

> Added support for Proxmox VE 4.x
> Added support for using the Notes field of a VM to define groups and variables:
> A well-formatted JSON object in the Notes field will be added to the _meta
> section for that VM.  In addition, the "groups" key of this JSON object may be
> used to specify group membership:
>
> { "groups": ["utility", "databases"], "a": false, "b": true }

For instance, you can use the following JSON code in a VM host:

```json
{ "groups": ["windows"] }
```

So if you want to exclude Windows machines, you could do the following:

```sh
# Run a playbook in every running Linux machine in Proxmox
ansible-playbook -i /etc/ansible/proxmox.py --limit='running,!windows' playbook-example/playbook.yml
```

## Examples

#### Show Linux distribution version for every VM in Proxmox cluster:

```sh
 ansible all -i /etc/ansible/proxmox.py --limit 'running,!windows' -m setup -u root -a 'filter=ansible_distribution_*'
```

Check more info about [Ansible setup module](http://docs.ansible.com/ansible/setup_module.html)
