#!/usr/bin/env python3

import multiprocessing
import subprocess
import itertools
import codecs
import socket
import struct
import glob
import re
import os

NETSTAT_LISTENING_TCP = "/bin/netstat --numeric-hosts --listening --program --tcp --inet --inet6"
NETSTAT_LISTENING_UDP = "/bin/netstat --numeric-hosts --listening --program --udp --inet --inet6"
TERMINAL_WIDTH = "/usr/bin/tput cols"  # could also be "stty size"

# oooh, look, a big dirty global dict collecting all our data without being passed
# around! call the programming police!
fds = {}


class Color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


COLOR_HEADER = Color.HEADER
COLOR_OKAY = Color.OKBLUE
COLOR_WARNING = Color.FAIL
COLOR_END = Color.END

# This should capture:
# 127.0.0.0/8
# 192.168.0.0/16
# 10.0.0.0/8
# 169.254.0.0/16
# 172.16.0.0/12
# ::1
# fe80::/10
# fc00::/7
# fd00::/8
NON_ROUTABLE_REGEX = r"""^((127\.) |
                           (192\.168\.) |
                           (10\.) |
                           (169\.254\.) |
                           (172\.1[6-9]\.) |
                           (172\.2[0-9]\.) |
                           (172\.3[0-1]\.) |
                           (::1) |
                           ([fF][eE]80)
                           ([fF][cCdD]))"""
likelyLocalOnly = re.compile(NON_ROUTABLE_REGEX, re.VERBOSE)


def run(thing):
    """ run any string as a shell invocation """
    # We don't use subprocess.check_output because we want to run all
    # processes async
    return subprocess.run(thing.split(), check=False, stdout=subprocess.PIPE)


def readOutput(ranCommand):
    return ranCommand.stdout.decode('utf-8').strip().splitlines()


def checkListenersSystemTools():
    # We intentionally don't check the output of these until after they
    # all run so they'll likely run in parallel without blocking.
    tcp = run(NETSTAT_LISTENING_TCP)
    udp = run(NETSTAT_LISTENING_UDP)
    terminalWidth = run(TERMINAL_WIDTH)

    tcp = readOutput(tcp)
    udp = readOutput(udp)

    cols = readOutput(terminalWidth)[0]
    cols = int(cols)

    # Remove first two header lines
    tcp = tcp[2:]
    udp = udp[2:]

    # This is slightly ugly, but 'udp' has one column missing in the
    # middle so our pid indices don't line up.
    grandResult = []
    for line in tcp:
        parts = line.split()
        proto = parts[0]
        addr = parts[3]
        pid = parts[6].split('/')[0]
        grandResult.append([int(pid), addr, proto])

    for line in udp:
        parts = line.split()
        proto = parts[0]
        addr = parts[3]
        pid = parts[5].split('/')[0]
        grandResult.append([int(pid), addr, proto])

    # Build map of pids to names...
    # This dict is pid -> completedCommand
    processes = {}
    for row in grandResult:
        pid = row[0]

        # Don't do redundant work.
        # We don't expect pid names to change across calls.
        if pid not in processes:
            processes[pid] = run(f"/bin/ps -p {pid} -o command=")

    # Now generate the result dict of pid -> pidName
    processName = {}
    for pid in processes:
        processName[pid] = readOutput(processes[pid])[0]

    # Print our own custom output header...
    proto = "Proto"
    addr = "Listening"
    pid = "PID"
    process = "Process"
    print(f"{COLOR_HEADER}{proto:^5} {addr:^25} {pid:>5} {process:^30}")

    # Sort results by pid...
    for row in sorted(grandResult, key=lambda x: x[0]):
        pid = row[0]
        addr = row[1]
        proto = row[2]
        process = processName[pid]

        # If IP address looks like it could be visible to the world,
        # throw up a color.
        # Note: due to port forwarding and NAT and other issues,
        #       this clearly isn't exhaustive.
        if not re.match(likelyLocalOnly, addr):
            colorNotice = COLOR_WARNING
        else:
            colorNotice = COLOR_OKAY

        output = f"{colorNotice}{proto:5} {addr:25} {pid:5} {process}"

        # Be a polite terminal citizen by limiting our width to user's width
        # (colors take up non-visible space, so add it to our col count)
        print(output[:cols + len(colorNotice)])

    print(COLOR_END)


if __name__ == "__main__":
    checkListenersSystemTools()
