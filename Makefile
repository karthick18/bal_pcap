PROTOC = protoc
PROTOS = bal.proto
PCAP_FILE = asfvolt16.pcap
BAL_PCAP = ./bal_pcap.py
TARGETS := bal_pb2

all: $(TARGETS)

bal_pb2: $(PROTOS)
	$(PROTOC) --python_out=. $(PROTOS)

run:
	$(BAL_PCAP) $(PCAP_FILE)

clean:
	rm -f *.pyc *~
