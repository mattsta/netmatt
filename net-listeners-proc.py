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


def procListeners():
    def processProc(name):
        def ipv6(addr):
            addr = codecs.decode(addr, "hex")
            # big endian / network byte order, double 64-bit
            addr = struct.unpack('>QQ', addr)
            # native byte order, double 64-bit
            addr = struct.pack('@QQ', *addr)
            addr = socket.inet_ntop(socket.AF_INET6, addr)
            return addr

        def ipv4(addr):
            # Instead of codecs.decode, we can just convert the 4 byte integer to hex directly
            # using python radix conversion.
            # Basically, int(addr, 16) EQUALS:
            # aOrig = addr
            # addr = codecs.decode(addr, "hex")
            # addr = struct.unpack(">L", addr)  # little endian, 4-byte integer, one-element tuple
            # assert(addr == (int(aOrig, 16),))
            addr = int(addr, 16)
            addr = struct.pack("<L", addr)  # little endian, 4-byte integer
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
                    if isUDP:
                        # These constants are based on enum offsets inside
                        # the Linux kernel itself. They aren't likely to ever
                        # change since they are hardcoded in utilities.
                        isListening = cxn[3] == "07"
                    else:
                        isListening = cxn[3] == "0A"

                    if not isListening:
                        continue

                    ip, port = cxn[1].split(':')
                    if ver:
                        ip = ipv6(ip)
                    else:
                        ip = ipv4(ip)

                    port = int(port, 16)
                    try:
                        port = socket.getservbyport(port)
                    except BaseException:
                        pass

                    fd = cxn[9]

                    # Pad the fd with [] because the /proc/pid/fd/* entries are like:
                    # socket:[fd]
                    # so later we can just split on : and compare the second
                    # half directly
                    fds[f"[{fd}]"] = {
                        'addr': ip, 'port': port, 'proto': f"{name}{ver}"}

    processProc("tcp")
    processProc("udp")


def processFd(fd):
    _, _, pid, _, _ = fd.split('/')
    try:
        target = os.readlink(fd)
    except BaseException:
        # file vanished, can't do anything else
        return

    if ':' not in target:
        return

    ostype, osfd = target.split(':')

    if osfd in fds:
        fds[osfd]['pid'] = pid
        try:
            with open(f"/proc/{pid}/cmdline", 'r') as cmd:
                fds[osfd]['cmd'] = cmd.read().split('\0')
        except BaseException:
            # files can vanish on us at any time and that's okay
            # But, since the file is gone, we want the entire fd
            # entry gone too:
            del fds[osfd]
            return


def addProcessNamesToFDs():
    allFDs = glob.iglob("/proc/*/fd/*")
    for fd in allFDs:
        processFd(fd)


def checkListenersProc():
    terminalWidth = run(TERMINAL_WIDTH)

    procListeners()
    addProcessNamesToFDs()
    tried = fds

    cols = readOutput(terminalWidth)[0]
    cols = int(cols)

    # Print our own custom output header...
    proto = "Proto"
    addr = "Listening"
    pid = "PID"
    process = "Process"
    print(f"{COLOR_HEADER}{proto:^5} {addr:^25} {pid:>5} {process:^30}")

    def thing(what):
        k, v = what
        return int(v['pid'])

    # Sort results by pid...
    for name, vals in sorted(tried.items(), key=thing):
        pid = vals['pid']
        addr = f"{vals['addr']}:{vals['port']}"
        proto = vals['proto']
        process = ' '.join(vals['cmd'])

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
    checkListenersProc()
