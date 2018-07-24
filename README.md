netstat Rewritten In Python
===========================

Welcome to netmatt — a simple `netstat -p |grep LISTEN` replacement in Python

## What Are The Files?

From oldest/worst to newest/best:

- `net-listeners-callout.py`
    - just reformats `netstat` output (requires root)
- `net-listeners-proc.py`
    - reads network state and matching commands from `/proc/[pid]/fd/*` directly (requires root)
- `net-listeners-proc-custom.py`
    - matches network state to commands by reading `/proc/pid_inode_map` created by kernel module in directory `pid_inode_map`
- `net-listeners-proc-unified.py`
    - uses `/proc/pid_inode_map` if exists; otherwise falls back to iterating `/proc/[pid]/fd/*`
    - it's the unification of `net-listeners-proc.py` and `net-listeners-proc-custom.py`
- `pid_inode_map`
    - Linux kernel module to create proc file `/proc/pid_inode_map` so non-root users can get a listing of which  processes own which IP:Port combinations

## What's the deetz?

Full writeup is [over at matt.sh/netmatt](https://matt.sh/netmatt)
