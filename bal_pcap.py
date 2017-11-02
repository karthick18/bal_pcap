#!/usr/bin/env python
from scapy.all import *
import sys
import time
import os
import stat
import re
import zlib
import bal_pb2
import tempfile
import select
from argparse import ArgumentParser
from bal_pcap_reader import rdpcap_streamer

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
                self.decode_packet(packet)

    def decode_packet(self, packet):
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
                         'BalAccTermInd' : bal_pb2.BalIndications(),
                         'BalFlowInd' : bal_pb2.BalIndications(),
                         'BalPktBearerChannelRxInd' : bal_pb2.BalIndications(),
                         'BalSubsTermInd' : bal_pb2.BalIndications(),
                         'BalSubsTermDiscoveryInd' : bal_pb2.BalIndications(),
                         'BalPktOmciChannelRxInd' : bal_pb2.BalIndications(),
                         'BalTmQueueIndInfo' : bal_pb2.BalIndications(),
                         'BalTmSchedIndInfo' : bal_pb2.BalIndications(),
                         'BalIfaceStat' : bal_pb2.BalIndications(),
                         'BalIfaceInd' : bal_pb2.BalIndications(),
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

class BalPcapStreamer(BalPcap):

    def __init__(self, pcap = None, options = None):
        if pcap is None:
            pcap = sys.stdin
        assert type(pcap) == file, 'pcap stream should be a file object'
        BalPcap.__init__(self, pcap, options = options)

    def stream(self, count = -1):
        status = self.pcap in select.select( [self.pcap], [], [], 1000000)[0]
        if status == True:
            rdpcap_streamer(self.pcap, self.decode_packet, count = count)
        else:
            print('Too long waiting for BAL packet. Returning')

if __name__ == '__main__':
    parser = ArgumentParser(description = 'Bal PCAP decoder')
    parser.add_argument('-pcap', '--pcap', default='asfvolt16.pcap',
                        help='Specify PCAP file to parse. Reads from stdin if not specified')
    parser.add_argument('-core-port', '--core-port', default=BalPcap.CORE_PORT,
                        type=int, help='Specify BAL core GRPC port')
    parser.add_argument('-indications-port', '--indications-port',
                        default = BalPcap.INDICATIONS_PORT, type=int,
                        help='Specify BAL indications adapter port')
    parser.add_argument('-stream', '--stream', action='store_true',
                        help = 'Enable streaming mode for decoding PCAP')
    parser.add_argument('-verbose', '--verbose', action='store_true',
                        help = 'Enable verbose mode for BAL pcap decoder')
    options = parser.parse_args()
    pcap = options.pcap

    if not os.access(pcap, os.F_OK):
        print('Unable to access pcap file %s' %pcap)
        sys.exit(127)

    if options.stream is False:
        bal_pcap = BalPcap(pcap, options)
        bal_pcap.decode()
        sys.exit(0)

    input_file = open(pcap, 'rb')
    bal_pcap_streamer = BalPcapStreamer(input_file, options = options)
    bal_pcap_streamer.stream(count = -1)
