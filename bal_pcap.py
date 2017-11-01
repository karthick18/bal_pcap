#!/usr/bin/env python

from scapy.all import *
import sys
import re
import zlib
import bal_pb2
from argparse import ArgumentParser

class BalPcap(object):
    CORE_PORT = 50051
    INDICATIONS_PORT = 60001

    def __init__(self, pcap, options = None):
        self.pcap = pcap
        self.core_port = self.CORE_PORT
        self.indications_port = self.INDICATIONS_PORT
        self.verbose = False
        if options is not None:
            self.core_port = options.core_port
            self.indications_port = options.indications_port
            self.verbose = options.verbose

    def decode(self):
        capture = rdpcap(self.pcap)
        for session in capture.sessions():
            for packet in capture.sessions()[session]:
                if packet.haslayer(TCP) and packet[TCP].payload:
                    dport = packet[TCP].dport
                    sport = packet[TCP].sport
                    if dport in [ self.core_port, self.indications_port ] or \
                       sport in [ self.core_port, self.indications_port ]:
                        if self.verbose:
                            packet.show()
                        status = self.parse(str(packet[TCP].payload))
                        if status == False:
                            if self.verbose:
                                hexdump(packet[TCP].payload)

    def parse(self, payload):
        bal_path_map = { 'BalApiInit' : bal_pb2.BalInit(),
                         'BalCfgSet'  : bal_pb2.BalCfg(),
                         'BalApiHeartbeat' : bal_pb2.BalHeartbeat(),
        }
        for path, obj in bal_path_map.iteritems():
            path_index = payload.find(path)
            if path_index > 0:
                payload_start = path_index + len(path)
                payload_len = len(payload)
                #we scan for a valid deserialize from the end
                for p in xrange(payload_start, payload_len):
                    deserialize_payload = payload[p:]
                    try:
                        obj.ParseFromString(deserialize_payload)
                        if self.verbose:
                            print('Successfully parsed path object %s at payload index %d' %(path, p))
                        print(path)
                        print('-'*40)
                        print(obj)
                        print('-'*40)
                        break
                    except:
                        continue
                else:
                    print('Unable to find payload for path %s' %(path))
                    return False

                return True

        return False

        @classmethod
        def extractHeaders(cls, payload):
            pattern = '([a-zA-Z-/]+).*?([a-zA-Z0-9\\-,.:\\+\\(\\);\\ ]+)@'
            headers = dict(re.findall(pattern, payload, re.UNICODE))
            return headers

        @classmethod
        def extractText(cls, headers, payload):
            m = 'identity,gzip'
            index = payload.index(m)
            if index >= 0:
                return payload[index + len(m):]
            return None

        @classmethod
        def dump_http2(cls, payload):
            text = None
            try:
                headers = cls.extractHeaders(str(payload))
                if headers:
                    text = cls.extractText(headers, str(payload))
            except:
                pass
            print(text)

if __name__ == '__main__':
    parser = ArgumentParser(description = 'Bal PCAP decoder')
    parser.add_argument('-pcap', '--pcap', default='asfvolt16.pcap',
                        help='Specify PCAP file to parse')
    parser.add_argument('-core-port', '--core-port', default=BalPcap.CORE_PORT,
                        type=int, help='Specify BAL core GRPC port')
    parser.add_argument('-indications-port', '--indications-port',
                        default = BalPcap.INDICATIONS_PORT, type=int,
                        help='Specify BAL indications adapter port')
    parser.add_argument('-verbose', '--verbose', action='store_true',
                        help = 'Enable verbose mode for BAL pcap decoder')

    options = parser.parse_args()
    bal_pcap = BalPcap(options.pcap, options)
    bal_pcap.decode()
