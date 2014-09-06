cap2wei ("kept-away")
=======

Simple, brutal scripts to convert HUAWEI TMF binary/text traces to PCAP / PLAIN LOGs

### Disclaimer
The scripts were hacked together quite too fast and barely tested, use at your own risk!


### Scripts:
- ptmf2pcap.pl: Convert binary PTMF to .PCAP and clear-text .LOG
- cap2wei.pl: Convert text PTMF (?) to .PCAP and clear-text .LOG

### Requirements:

- perl
- text2pcap (wireshark)
- bit-twist (http://bittwist.sourceforge.net )

## Usage for BINARY PTMF files:
```
./ptmf2pcap.pl {filename.ptmf}
```

## Usage for TEXT PTMF exports:
```
./cap2wei.pl {filename.txt}
```


### Output Files:
```
PCAP: {filename}.pcap
LOG:  {filename}.log
```

### Text Format: Headers
```
 	[No.                   ] INT
 	[TimeStamp             ] %Y-%m-%d %H:%M:%S.
 	[Source Address        ] IPv4
 	[Source Port           ] INT
 	[Destination Address   ] IPv4
 	[Destination Port      ] INT
 	[Message Interface Type] STRING
 	[Message Type          ] STRING
 	[Hex Message           ] HEX
```
