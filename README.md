# Ansible-Proxmox-inventory

## About

Proxmox dynamic inventory for Ansible. Based on [original plugin](https://raw.githubusercontent.com/ansible/ansible/devel/contrib/inventory/proxmox.py) from Mathieu Gauthier-Lafaye

Changelog:
- Added option to ignore invalid SSL certificate (by @bmillemathias) [PR](https://github.com/ansible/ansible/pull/17247)
- Compatible with a Proxmox cluster (by @xezpeleta)
- Added group 'running' (by @xezpeleta)

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
export PROXMOX_URL=https://10.0.0.1:8006/
export PROXMOX_USERNAME=apiuser@pve
export PROXMOX_PASSWORD=apiuser1234
export PROXMOX_INVALID_CERT=False
```

So now you can check it again without credential parameters:

```sh
python /etc/ansible/proxmox.py --list --pretty
```

Once you get this working, you can include the dynamic inventory in your ansible commands:

```sh
ansible -i /etc/ansible/proxmox.py ...
```

## Tricks

If you prefer, you can limit the commands to the group "running":

```sh
ansible-playbook -i /etc/ansible/proxmox.py --limit 'running' playbook.yml
```

Thanks to Matt Harris, you can use the Notes field in Proxmox to add a host to a group:

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
ansible-playbook -i /etc/ansible/proxmox.py --limit 'running,!windows' playbook.yml
```
