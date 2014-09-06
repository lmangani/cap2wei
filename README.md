cap2wei
=======

Simple scripts to convert HUAWEI TMF binary/text traces to PCAP / PLAIN LOGs

### Disclaimer
The scripts were hacked together quite fast and barely tested, use at your own risk!


## Scripts:
- ptmf2pcap.pl: Convert binary PTMF to .PCAP and clear-text .LOG
- cap2wei.pl: Convert text PTMF (?) to .PCAP and clear-text .LOG

### Requirements:

- perl
- text2pcap (wireshark)
- bit-twist (http://bittwist.sourceforge.net )

## Usage for BINARY PTMF:
```
./ptmf2pcap.pl {filename.ptmf}
```

## Usage for TEXT PTMF:
```
./cap2wei.pl {filename.txt}
```


### Output Files:
```
PCAP: {filename}.pcap
LOG:  {filename}.log
```

### Header Formats:
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
