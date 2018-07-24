#!/usr/bin/env python3

""" Output a colorized list of listening addresses with owners.

This tool parses files in /proc directly to obtain the list
of IPv4 and IPv6 addresses listening on tcp, tcp6, udp, and udp6 ports
also with pids of processes responsible for the listening.

Due to permission restrictions on Linux, script must be run as root
to determine which pids match which listening sockets.

This is also something like:
    osqueryi "select po.pid, rtrim(p.cmdline), po.family, po.local_address, po.local_port from process_open_sockets as po JOIN processes as p ON po.pid=p.pid WHERE po.state='LISTEN';"

"""

import collections
import subprocess
import codecs
import socket
import struct
import glob
import sys
import re
import os

TERMINAL_WIDTH = "/usr/bin/tput cols"  # could also be "stty size"

ONLY_LOWEST_PID = False

# oooh, look, a big dirty global dict collecting all our data without being
# passed around! call the programming police!
inodes = {}


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


def procListeners():
    """ Wrapper to parse all IPv4 tcp udp, and, IPv6 tcp6 udp6 listeners. """

    def processProc(name):
        """ Process IPv4 and IPv6 versions of listeners based on ``name``.

        ``name`` is either 'udp' or 'tcp' so we parse, for each ``name``:
            - /proc/net/[name]
            - /proc/net/[name]6

        As in:
            - /proc/net/tcp
            - /proc/net/tcp6
            - /proc/net/udp
            - /proc/net/udp6
        """

        def ipv6(addr):
            """ Convert /proc IPv6 hex address into standard IPv6 notation. """
            # turn ASCII hex address into binary
            addr = codecs.decode(addr, "hex")

            # unpack into 4 32-bit integers in big endian / network byte order
            addr = struct.unpack('!LLLL', addr)

            # re-pack as 4 32-bit integers in system native byte order
            addr = struct.pack('@IIII', *addr)

            # now we can use standard network APIs to format the address
            addr = socket.inet_ntop(socket.AF_INET6, addr)
            return addr

        def ipv4(addr):
            """ Convert /proc IPv4 hex address into standard IPv4 notation. """
            # Instead of codecs.decode(), we can just convert a 4 byte hex
            # string to an integer directly using python radix conversion.
            # Basically, int(addr, 16) EQUALS:
            # aOrig = addr
            # addr = codecs.decode(addr, "hex")
            # addr = struct.unpack(">L", addr)
            # assert(addr == (int(aOrig, 16),))
            addr = int(addr, 16)

            # system native byte order, 4-byte integer
            addr = struct.pack("=L", addr)
            addr = socket.inet_ntop(socket.AF_INET, addr)
            return addr

        isUDP = name == "udp"

        # Iterate four files: /proc/net/{tcp,udp}{,6}
        # ipv4 has no prefix, while ipv6 has 6 appended.
        for ver in ["", "6"]:
            with open(f"/proc/net/{name}{ver}", 'r') as proto:
                proto = proto.read().splitlines()
                proto = proto[1:]  # drop header row

                for cxn in proto:
                    cxn = cxn.split()

                    # /proc/net/udp{,6} uses different constants for LISTENING
                    if isUDP:
                        # These constants are based on enum offsets inside
                        # the Linux kernel itself. They aren't likely to ever
                        # change since they are hardcoded in utilities.
                        isListening = cxn[3] == "07"
                    else:
                        isListening = cxn[3] == "0A"

                    # Right now this is a single-purpose tool so if process is
                    # not listening, we avoid further processing of this row.
                    if not isListening:
                        continue

                    ip, port = cxn[1].split(':')
                    if ver:
                        ip = ipv6(ip)
                    else:
                        ip = ipv4(ip)

                    port = int(port, 16)
                    inode = cxn[9]

                    # We just use a list here because creating a new sub-dict
                    # for each entry was noticably slower than just indexing
                    # into lists.
                    inodes[int(inode)] = [ip, port, f"{name}{ver}"]

    processProc("tcp")
    processProc("udp")


def appendToInodePidMap(fd, inodePidMap):
    """ Take a full path to /proc/[pid]/fd/[fd] for reading.

    Populates both pid and full command line of pid owning an inode we
    are interested in.

    Basically finds if any inodes on this pid is a listener we previously
    recorded into our ``inodes`` dict. """
    _, _, pid, _, _ = fd.split('/')
    try:
        target = os.readlink(fd)
    except FileNotFoundError:
        # file vanished, can't do anything else
        return

    if target.startswith("socket"):
        ostype, inode = target.split(':')
        # strip brackets from fd string (it looks like: [fd])
        inode = int(inode[1:-1])
        inodePidMap[inode].append(int(pid))


def addProcessNamesToInodes():
    """ Loop over every fd in every process in /proc.

    The only way to map an fd back to a process is by looking
    at *every* processes fd and extracting backing inodes.

    It's basically like a big awkward database join where you don't
    have an index on the field you want.

    Also, due to Linux permissions (and Linux security concerns),
    only the root user can read fd listing of processes not owned
    by the current user. """

    # glob glob glob it all
    allFDs = glob.iglob("/proc/*/fd/*")
    inodePidMap = collections.defaultdict(list)

    for fd in allFDs:
        appendToInodePidMap(fd, inodePidMap)

    for inode in inodes:
        if inode in inodePidMap:
            for pid in inodePidMap[inode]:
                try:
                    with open(f"/proc/{pid}/cmdline", 'r') as cmd:
                        # /proc command line arguments are delimited by
                        # null bytes, so undo that here...
                        cmdline = cmd.read().split('\0')
                        inodes[inode].append((pid, cmdline))
                except BaseException:
                    # files can vanish on us at any time (and that's okay!)
                    # But, since the file is gone, we want the entire fd
                    # entry gone too:
                    pass  # del inodes[inode]


def checkListenersProc():
    terminalWidth = run(TERMINAL_WIDTH)

    procListeners()
    addProcessNamesToInodes()
    tried = inodes

    try:
        cols = readOutput(terminalWidth)[0]
        cols = int(cols)
    except BaseException:
        cols = 80

    # Print our own custom output header...
    proto = "Proto"
    addr = "Listening"
    pid = "PID"
    process = "Process"
    print(f"{COLOR_HEADER}{proto:^5} {addr:^25} {pid:>5} {process:^30}")

    # Could sort by anything: ip, port, proto, pid, command name
    # (or even the fd integer if that provided any insight whatsoever)
    def compareByPidOrPort(what):
        k, v = what
        # v = [ip, port, proto, pid, cmd]
        # - OR -
        # v = [ip, port, proto]

        # If we're not running as root we can't pid and command mappings for
        # the processes of other users, so sort the pids we did find at end
        # of list and show UNKNOWN entries first
        # (because the lines will be shorter most likely so the bigger visual
        # weight should be lower in the display table)
        try:
            # Pid available! Sort by first pid, subsort by IP then port.
            return (1, v[3], v[0], v[1])
        except BaseException:
            # No pid available! Sort by port number then IP then... port again.
            return (0, v[1], v[0], v[1])

    # Sort results by pid...
    for name, vals in sorted(tried.items(), key=compareByPidOrPort):
        attachedPids = vals[3:]
        if attachedPids:
            desc = [f"{pid:5} {' '.join(cmd)}" for pid, cmd in vals[3:]]
        else:
            # If not running as root, we won't have pid or process, so use
            # defaults
            desc = ["UNKNOWN (must be root for global pid mappings)"]

        port = vals[1]
        try:
            # Convert port integer to service name if possible
            port = socket.getservbyport(port)
        except BaseException:
            # If no match, just use port number directly.
            pass

        addr = f"{vals[0]}:{port}"
        proto = vals[2]

        # If IP address looks like it could be visible to the world,
        # throw up a color.
        # Note: due to port forwarding and NAT and other issues,
        #       this clearly isn't exhaustive.
        if re.match(likelyLocalOnly, addr):
            colorNotice = COLOR_OKAY
        else:
            colorNotice = COLOR_WARNING

        isFirstLine = True
        for line in desc:
            if isFirstLine:
                output = f"{colorNotice}{proto:5} {addr:25} {line}"
                isFirstLine = False
            else:
                output = f"{' ':31} {line}"

            # Be a polite terminal citizen by limiting our width to user's width
            # (colors take up non-visible space, so add it to our col count)
            print(output[:cols + (len(colorNotice) if isFirstLine else 0)])

            if ONLY_LOWEST_PID:
                break

    print(COLOR_END)


if __name__ == "__main__":
    # cheap hack garbage way of setting one option
    # if we need more options, obviously pull in argparse
    if len(sys.argv) > 1:
        ONLY_LOWEST_PID = True
    else:
        ONLY_LOWEST_PID = False

    checkListenersProc()
