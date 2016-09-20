#!/usr/bin/env python

import os
from collections import deque, defaultdict, namedtuple
import pickle
import sys

IPPort = namedtuple('IPPort', ['ip', 'port'])


##############################################################################
class ChatterStats(object):
    """
    Collect information about what network connections are active on a server
    Should be run regularly.
    :: sample_range is the number of samples to measure over
    :: hitrate is how many times that connection has to appear over the sample
    range to be considered permanent
    :: statefile is where to store the state information

    """
    def __init__(self, sample_range=10, hitrate=9, statefile='/var/run/chatter.pickle'):
        self.statefile = statefile
        self.sample_range = sample_range
        self.hitrate = hitrate
        self.now_ports = []
        self.now_conns = []

    ##########################################################################
    def collect(self):
        with os.popen('netstat -an') as fh:
            for line in fh:
                bits = line.strip().split()
                if bits[0] not in ('udp', 'tcp', 'udp4', 'tcp4'):
                    continue
                if bits[-1] == 'LISTEN':
                    self.listener(bits[3])
                if bits[-1] == 'ESTABLISHED':
                    local = bits[3]
                    remote = bits[4]
                    self.connection(local, remote)
        self.history_conns.append(self.now_conns)
        self.history_ports.append(self.now_ports)

    ##########################################################################
    def breakdown(self, ippstr):
        """ Handle multiple formats for address / port """
        # 10.0.2.15:58378
        # 0.0.0.0:22
        # 192.168.0.6.58303
        # *.17500
        if ippstr.startswith('*'):
            ip = '*'
            port = ippstr.split('.')[-1]
        if ':' in ippstr:
            ip, port = ippstr.split(':')
        if ippstr.count('.') == 4:
            ip = '.'.join(ippstr.split('.')[:4])
            port = ippstr.split('.')[-1]
        if ip in ('0.0.0.0', '*'):
            ip = 'all'
        return IPPort(ip, port)

    ##########################################################################
    def listener(self, liststr):
        p = self.breakdown(liststr)
        self.now_ports.append(p)

    ##########################################################################
    def gen_analyze(self, history):
        data = defaultdict(int)
        results = []
        for sample in history:
            for obj in sample:
                data[str(obj)] += 1
        for obj, cnt in data.items():
            if cnt >= self.hitrate:
                results.append(obj)
        return results

    ##########################################################################
    def analyze(self):
        ports = self.gen_analyze(self.history_ports)
        conns = self.gen_analyze(self.history_conns)
        return {'ports': ports, 'connections': conns}

    ##########################################################################
    def connection(self, localstr, remotestr):
        local = self.breakdown(localstr)
        remote = self.breakdown(remotestr)
        self.now_conns.append((local, remote))

    ##########################################################################
    def load(self, filename=None):
        if filename is None:
            filename = self.statefile
        try:
            with open(filename) as fh:
                self.history_ports = pickle.load(fh)
                self.history_conns = pickle.load(fh)
        except Exception as exc:
            sys.stderr.write("Couldn't load %s: %s\n" % (filename, str(exc)))
            self.history_ports = deque(maxlen=self.sample_range)
            self.history_conns = deque(maxlen=self.sample_range)

    ##########################################################################
    def save(self, filename=None):
        if filename is None:
            filename = self.statefile
        with open(filename, 'w') as fh:
            pickle.dump(self.history_ports, fh)
            pickle.dump(self.history_conns, fh)


##############################################################################
def main():
    s = ChatterStats(statefile='/tmp/chatter.pickle')
    s.load()
    s.collect()
    print s.analyze()
    s.save()

##############################################################################
if __name__ == "__main__":
    main()

# EOF
