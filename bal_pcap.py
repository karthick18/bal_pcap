#!/usr/bin/env python

from scapy.all import *
import sys
import re
import zlib
import bal_pb2

def extractHeaders(payload):
    pattern = '([a-zA-Z-/]+).*?([a-zA-Z0-9\\-,.:\\+\\(\\);\\ ]+)@'
    headers = dict(re.findall(pattern, payload, re.UNICODE))
    print(headers)
    return headers

def extractText(headers, payload):
    m = 'identity,gzip'
    index = payload.index(m)
    if index >= 0:
        return payload[index + len(m):]
    return None

def dump_http2(payload):
    text = None
    try:
        headers = extractHeaders(str(payload))
        if headers:
            text = extractText(headers, str(payload))
    except:
        pass
    print(text)

def parse_bal(capture):
    for session in capture.sessions():
        for packet in capture.sessions()[session]:
            if packet.haslayer(TCP) and packet[TCP].payload:
                if packet[TCP].dport == 60001:
                    packet.show()
                    print(str(packet[TCP].payload))
                    dump_http2(packet[TCP].payload)

if __name__ == '__main__':
    pcap = 'asf.pcap'
    if len(sys.argv) > 1:
        pcap = sys.argv[1]
    capture = rdpcap(pcap)
    parse_bal(capture)
from scapy.all import *
import sys
import re
import zlib

def extractHeaders(payload):
    pattern = '([a-zA-Z-/]+).*?([a-zA-Z0-9\\-,.:\\+\\(\\);\\ ]+)@'
    headers = dict(re.findall(pattern, payload, re.UNICODE))
    print(headers)
    return headers

def extractText(headers, payload):
    m = 'identity,gzip'
    index = payload.index(m)
    if index >= 0:
        return payload[index + len(m):]
    return None

def dump_http2(payload):
    text = None
    try:
        headers = extractHeaders(str(payload))
        if headers:
            text = extractText(headers, str(payload))
    except:
        pass
    print(text)

def parse_bal(payload):
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
            for p in range(payload_start, payload_len):
                deserialize_payload = payload[p:]
                try:
                    obj.ParseFromString(deserialize_payload)
                    #print('Successfully parsed path object %s at payload index %d' %(path, p))
                    print(path)
                    print('-'*40)
                    print(str(obj))
                    print('-'*40)
                    break
                except:
                    continue
            else:
                print('Unable to find payload for path %s' %path)
                return False
            return True
    return False

def parse_pcap(capture):
    for session in capture.sessions():
        for packet in capture.sessions()[session]:
            if packet.haslayer(TCP) and packet[TCP].payload:
                dport = packet[TCP].dport
                sport = packet[TCP].sport
                if dport in [ 50051, 60001 ] or sport in [ 50051, 60001]:
                    status = parse_bal(str(packet[TCP].payload))
                    if status == False:
                        pass
                        #hexdump(packet[TCP].payload)
                        #packet.show()
                    #dump_http2(packet[TCP].payload)

if __name__ == '__main__':
    pcap = 'asf.pcap'
    if len(sys.argv) > 1:
        pcap = sys.argv[1]
    capture = rdpcap(pcap)
    parse_pcap(capture)
