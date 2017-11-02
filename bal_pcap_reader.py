from scapy.all import *
import struct
import time
import os

class BalPcapReader(object):

    def init_ng(self):
        # A list of (linktype, snaplen); will be populated by IDBs.
        self.interfaces = []
        self.blocktypes = {
            1: self.read_block_idb,
            6: self.read_block_epb,
        }
        # see https://github.com/pcapng/pcapng
        blocklen, magic = self.f.read(4), self.f.read(4)
        if magic == "\x1a\x2b\x3c\x4d":
            self.endian = ">"
        elif magic == "\x4d\x3c\x2b\x1a":
            self.endian = "<"
        else:
            raise Scapy_Exception("Not a pcapng capture file (bad magic)")

        self.f.seek(0)

    def read_packet_ng(self, size=MTU):
        rp = self.__read_packet_ng(size=size)
        if rp is None:
            return None
        s, (linktype, sec, usec, wirelen) = rp
        try:
            p = conf.l2types[linktype](s)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            p = conf.raw_layer(s)
        p.time = sec+0.000001*usec
        return p

    def __read_packet_ng(self, size=MTU):
        """Read blocks until it reaches either EOF or a packet, and
        returns None or (packet, (linktype, sec, usec, wirelen)),
        where packet is a string.

        """
        while True:
            try:
                blocktype, blocklen = struct.unpack(self.endian + "2I",
                                                    self.f.read(8))
            except struct.error:
                return None
            block = self.f.read(blocklen - 12)
            try:
                if (blocklen,) != struct.unpack(self.endian + 'I',
                                                self.f.read(4)):
                    raise Scapy_Exception(
                        "Invalid pcapng block (bad blocklen)"
                    )
            except struct.error:
                return None
            res = self.blocktypes.get(blocktype,
                                      lambda block, size: None)(block, size)
            if res is not None:
                return res

    def read_block_idb(self, block, _):
        """Interface Description Block"""
        self.interfaces.append(struct.unpack(self.endian + "HxxI", block[:8]))

    def read_block_epb(self, block, size):
        """Enhanced Packet Block"""
        intid, sec, usec, caplen, wirelen = struct.unpack(self.endian + "5I",
                                                          block[:20])
        return (block[20:20 + caplen][:size],
                (self.interfaces[intid][0], sec, usec, wirelen))

    def __init__(self, fdesc, dispatch = None):
        self.f = fdesc
        self.filename = 'unused'
        if dispatch is None:
            dispatch = lambda p: None
        self.dispatch = dispatch
        self.ng = False
        magic = self.f.read(4)
        if magic == "\x0a\x0d\x0d\x0a": # PcapNg:
            self.ng = True
            self.init_ng()
            return
        elif magic == "\xa1\xb2\xc3\xd4": #big endian
            self.endian = ">"
        elif magic == "\xd4\xc3\xb2\xa1": #little endian
            self.endian = "<"
        else:
            raise Scapy_Exception(
                "Not a pcap capture file (bad magic: %r)" % magic
            )
        hdr = self.f.read(20)
        if len(hdr)<20:
            raise Scapy_Exception("Invalid pcap file (too short)")
        vermaj, vermin, tz, sig, snaplen, linktype = struct.unpack(
            self.endian + "HHIIII", hdr
        )
        self.linktype = linktype
        try:
            self.LLcls = conf.l2types[self.linktype]
        except KeyError:
            warning("PcapReader: unknown LL type [%i]/[%#x]. Using Raw packets" % (self.linktype,self.linktype))
            self.LLcls = conf.raw_layer

    def __read_packet(self, size=MTU):
        """return a single packet read from the file

        returns None when no more packets are available
        """
        hdr = self.f.read(16)
        if len(hdr) < 16:
            return None
        sec,usec,caplen,wirelen = struct.unpack(self.endian+"IIII", hdr)
        s = self.f.read(caplen)[:size]
        return s,(sec,usec,wirelen) # caplen = len(s)

    def read_packet(self, size=MTU):
        if self.ng is True:
            return self.read_packet_ng(size = size)
        rp = self.__read_packet(size=size)
        if rp is None:
            return None
        s,(sec,usec,wirelen) = rp

        try:
            p = self.LLcls(s)
        except KeyboardInterrupt:
            raise
        except:
            if conf.debug_dissector:
                raise
            p = conf.raw_layer(s)
        p.time = sec+0.000001*usec
        return p

    def stream_all(self, count=-1):
        """read the packets and dispatch to a pcap streamer
        """
        while count != 0:
            count -= 1
            p = self.read_packet()
            if p is None:
                break
            self.dispatch(p)

def rdpcap_streamer(stream, dispatch, count = -1):
    assert type(stream) == file
    assert dispatch != None, 'pcap dispatch streamer should not be None'
    stream.seek(0)

    def file_size():
        return os.fstat(stream.fileno()).st_size

    size = 0
    while True:
        size = file_size()
        if size == 0:
            time.sleep(1)
        else:
            break

    pcap_reader = BalPcapReader(stream, dispatch = dispatch)
    last_size = size
    while True:
        pcap_reader.stream_all(count = count)
        while last_size == size:
            time.sleep(1)
            size = file_size()
        stream.seek(last_size)
        last_size = size
