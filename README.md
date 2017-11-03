# bal_pcap
To decode bal voltha adapter grpc packets.
The GRPC bal packet is encoded as a HTTP2/protobuf packet.

In order to deserialize the protobuf packet, we need to
decode the field/tag:value binary format which is cool and optimized encoding.

However we also would need to map it to the grpc descriptor out.

Do you really want to replicate Jeff Dean's brilliance? :)

We just reverse engineer the bal api packet using the logic from which it was created.

We run it against the bal_pb2 serializer based on the Path/object we are parsing.
And then dump the packet.

Right now, it supports BalInit, BalCfgSet,BalHeartbeat and BalIndications which should make for a good starting line up.

The packet capture asfvolt16.pcap here was created using my bal_voltha project at:

http://github.com/karthick18/bal_voltha
and simulating a run of activation with bal edge core.

To quick test:
make run
and watch it decode asfvolt16.pcap sample.

In order to generate the pcap in a real environment, just run a tcpdump against
the bal grpc and indications port.

Like:
```
tcpdump -i any -w ~/asf.pcap port 50051 or port 60001
```

```
make run
./bal_pcap.py asfvolt16.pcap
BalApiInit
----------------------------------------
voltha_adapter_ip_port: "172.17.0.1:60001"

----------------------------------------
BalCfgSet
----------------------------------------
hdr {
}
cfg {
  key {
  }
  data {
    admin_state: BAL_STATE_UP
  }
}
device_id: "0001cb6cfb7b3ffb"

----------------------------------------
BalApiHeartbeat
----------------------------------------
device_id: "0001cb6cfb7b3ffb"

----------------------------------------
```

In order to decode the packets in real-time as they are captured by tcpdump,
do the following:

```
sudo tcpdump -i any -w /tmp/bal_stream.pcap -xxx -vvv -U -p tcp port 50051 or port 60001

And on another shell:

./bal_pcap.py --pcap /tmp/bal_stream.pcap --stream

And watch the BAL grpc packets being decoded as they arrive.
```
