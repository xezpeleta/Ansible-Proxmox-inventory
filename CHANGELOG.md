# Changelog

## v1.0.4
- Create groups based on tags (by @apigban) https://github.com/xezpeleta/Ansible-Proxmox-inventory/pull/51

## v1.0.3
- Improved network interface filtering (by @graytonio) [#43](https://github.com/xezpeleta/Ansible-Proxmox-inventory/pull/43)[#50](https://github.com/xezpeleta/Ansible-Proxmox-inventory/pull/50)
- Added function to take "hostname" as ansible_hostname from API if LXC uses DHCP-leases (by @standadHD) [#47](https://github.com/xezpeleta/Ansible-Proxmox-inventory/pull/47)

## v1.0.2
- Proxmox v7 compatibility check if template key exists (by @maynero) [#39](https://github.com/xezpeleta/Ansible-Proxmox-inventory/pull/39)

## v1.0.1
- Ommit group when OS id is empty (d7b0139)

## v1.0.0
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
- Fixed UnboundLocalError (@hosfeld) [#25]
- Fixed python3 errors (@akhan23wgu) [#26]
- Fix QEMU guest agent IP address retrieval (@johnpc35) [#31]
- Added skipping 596 error code (@srufle) [33]
- Added Proxmox osinfo on host_vars, create group base on OS, and fix issue #34 (@maynero) [#36]
