#!/usr/bin/env python3

""" Output a colorized list of listening addresses with owners.

This tool parses the output of ``netstat`` directly to obtain the list
of IPv4 and IPv6 addresses listening on tcp, tcp6, udp, and udp6 ports
also with pids of processes responsible for the listening.

The downside here is to obtain the full command name (netstat truncates
at 20 characters), we need to call ``ps`` again for each pid we have,
which is even more external commands.

Must be run as root due to netstat needing root for pid to socket mappings.

See ``net-listeners-proc.py`` for a much faster implementation because it
parses /proc directly and doesn't need to call out to external proceses."""

import subprocess
import re

NETSTAT_LISTENING = "/bin/netstat --numeric-hosts --listening --program --tcp --udp --inet --inet6"
TERMINAL_WIDTH = "/usr/bin/tput cols"  # could also be "stty size"


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
    """ Run any string as an async command invocation. """
    # We don't use subprocess.check_output because we want to run all
    # processes async
    return subprocess.Popen(thing.split(), stdout=subprocess.PIPE)


def readOutput(ranCommand):
    """ Return array of rows split by newline from previous invocation. """
    stdout, stderr = ranCommand.communicate()
    return stdout.decode('utf-8').strip().splitlines()


def checkListenersSystemTools():
    # We intentionally don't check the output of these until after they
    # all run so they'll likely run in parallel without blocking.
    listening = run(NETSTAT_LISTENING)
    terminalWidth = run(TERMINAL_WIDTH)

    listening = readOutput(listening)

    try:
        cols = readOutput(terminalWidth)[0]
        cols = int(cols)
    except BaseException:
        cols = 80

    # Remove first two header lines
    listening = listening[2:]

    # This is slightly ugly, but 'udp' has one column missing in the
    # middle so our pid indices don't line up.
    grandResult = []
    for line in listening:
        parts = line.split()

        # "udp" rows have one less column in the middle, so
        # our pid offset is lower than "tcp" rows:
        if parts[0].startswith("udp"):
            pid = parts[5].split('/')[0]
        else:
            pid = parts[6].split('/')[0]

        proto = parts[0]
        addr = parts[3]
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
        if re.match(likelyLocalOnly, addr):
            colorNotice = COLOR_OKAY
        else:
            colorNotice = COLOR_WARNING

        output = f"{colorNotice}{proto:5} {addr:25} {pid:5} {process}"

        # Be a polite terminal citizen by limiting our width to user's width
        # (colors take up non-visible space, so add it to our col count)
        print(output[:cols + len(colorNotice)])

    print(COLOR_END)


if __name__ == "__main__":
    checkListenersSystemTools()
