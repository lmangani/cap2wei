#!/usr/bin/perl
# 
# App: ptmf2pcap
# Version: 0.1b (07/09/2014)
# Author: L. Mangani, C. Mangani
# Description: Script to convert HUAWEI PTMF binary trace to PCAP & Clear TEXT
#
# ==========================================================================
# The MIT License (MIT) Copyright © 2014 Lorenzo Mangani, Celeste Mangani
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this 
# software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, 
# publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies 
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# ==========================================================================
#
# ALPHA STATUS & UNTESTED! USE AT YOUR OWN RISK!
#
# TO-DO: 
#       - Add Timestamps from tmf header
#       - Find out what else is there


use strict;
use warnings;
use IPC::Cmd qw[can_run run];

print "ptmf2pcap: Convert HUAWEI PTMF Binary to PCAP/PLAINTEXT \n\n";

my $full_path = can_run('text2pcap') or warn 'text2pcap is not installed! Please install wireshark \n';
$full_path = can_run('bittwiste') or warn 'bittwiste is not installed! Please install from http://bittwist.sourceforge.net \n';

my $filename = $ARGV[0];

if (! -e $filename || @ARGV == 0 ) { 
	print "oops, source file not found!\n"; usage(); 
	print "Usage: \n";
	print "       ./ptmf2pcap.pl {filename.ptmf} \n\n";
	exit();
}

my $target = $ARGV[0];
$target =~ s{\.[^.]+$}{};
my $tmp = "/tmp/$target-tmp";

if ( ! -d "$tmp" ) {
	system("mkdir $tmp");
}

system("rm -rf ./$target-ptmf.log");

print "Parsing & Converting records....";

#my $hexdata = `cat $filename | xxd -p | tr -d '\n'`;
my $hexdata = `cat $filename`;

my $hexdata_pack = unpack "H*", $hexdata;

my @values = split('6d736730', $hexdata_pack);

my $count = -1;
my $hdr;
my $from_ip = '';
my $to_ip = '';
my $from_port = 0;
my $to_port = 0;
my $ts;
my $command;
my ($t_ms,$t_ts);

foreach my $val (@values) {
    $count++;
    if ($count >= 1 ) {   
    # print "## RECORD $count\n";
    # Header
    my $head =  substr $val, 1,193;
	if ( $head ) {
		# Parse Header (reversed, work in progress!)
		$hdr = unpack "A*", $head;
		# print "HDR: $hdr \n";
		
		# Parse SRC, DST IPs
		$from_ip =  substr "$hdr", 107,8; #114,121
		$from_ip = join '.', unpack "C*", pack "H*", $from_ip;
		$to_ip =  substr "$hdr", 145,8;
		$to_ip = join '.', unpack "C*", pack "H*", $to_ip;
		
		# Parse SRC, DST PORTs
		$from_port =  substr "$hdr", 141,2;
		$from_port = "$from_port" .  substr "$hdr", 139,2;
		$to_port =  substr "$hdr", 179,2;
		$to_port = "$to_port" .  substr "$hdr", 177,2;
		$from_port = hex($from_port);
		$to_port = hex($to_port);

		# Time
                $t_tm =  substr "$hdr", 55,6;
                $t_tm = join ':', unpack "C*", pack "H*", $t_tm;
                # Milliseconds
                $t_ms =  substr "$hdr", 63,8;
                $t_ms = hex($t_ms);
                #print "MSEC: $t_ms \n";

                # Build %h:%m:%s.
                $t_ts = $t_tm.".".$t_ms;

	}

    # Hex Message, stripped
    $val =  substr $val, 194;
    my $log = "$val";

      $log =~ s/(([0-9a-f][0-9a-f])+)/pack('H*', $1)/ie;
      if ( $log =~ /[[:alpha:]]/ ) { 
	# HEX Packet
	# $val = unpack "H*", $log;
	$val =~ s/[^ ]{2}(?=[^\n ])/$& /g;
    	#$val =  substr $val, 56;
    	$val =~ s/^/00000 /;

    	# Inkject TS extracted from header
        $val = $t_ts."\n".$val;

	#$val = $hdr.$val;
    	# Write to temp file and send to text2cap
			my $filename = $tmp.'/pt'.$count.'.txt';
			open(my $fh, '>', $filename) or die "Could not open file '$filename' $!";
			print $fh $val;
			close $fh;

		$command = "text2pcap -q -t '%H:%M:%S.' -u $from_port,$to_port -i 17 $tmp/pt$count.txt $tmp/pt$count.pcap";
		system($command);

		if ($from_port > 1) {
			system("bittwiste -I $tmp/pt$count.pcap -O $tmp/pt$count-2.pcap -T ip -s $from_ip > /dev/null 2>&1");
			system("bittwiste -I $tmp/pt$count-2.pcap -O $tmp/pt$count-3.pcap -T ip -d $to_ip > /dev/null 2>&1");
			system("rm -rf $tmp/pt$count.pcap");
			system("rm -rf $tmp/pt$count-2.pcap");
		}

		#if ( -T "$siplog" ) {
			my $filelog =  './'.$target.'-ptmf.log';
			#my $filelog = '/tmp/siplog.log';
			open(my $fh2, '>>', $filelog) or die "Could not open log file '$filename' $!";
			print $fh2 "$from_ip:$from_port -> $to_ip:$to_port\n$log\n";
			#print $fh2 $log;
			close $fh2;
		#}

      }
    } else {
	# Initial Header w/ date
	# print "$val";	
        $ts =  substr $val, -32, 32;
        $ts =~ s/(([0-9a-f][0-9a-f])+)/pack('H*', $1)/ie;
	#print "\nREPORT DATE: $ts\n";
	#my $time = Time::Piece->strptime( $ts, "%Y-%m-%d %H:%M");
	#print "\nTS: $time\n";
    }

}
		# Merge pcaps
		$command = "mergecap -w $target-ptmf.pcap $tmp/pt*.pcap";
		system($command);
		# Cleanup
		#$command = "rm -rf $tmp";
		#system($command);



print "Done!\n\n";

print "Original: $filename \n";
print "PCAP:     $target-ptmf.pcap \n";
print "TEXT-Log: $target-ptmf.siplog \n\n";

exit 0;
