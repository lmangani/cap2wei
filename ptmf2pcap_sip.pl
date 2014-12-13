#!/usr/bin/perl
# 
# App: ptmf2pcap
# Version: 0.3a (12/12/2014)
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
#       - Find out what else is the header (protocol type, etc)


use strict;
use warnings;
use IPC::Cmd qw[can_run run];
use Encode;
use Encode::Guess;
use Net::PcapWriter;
use Date::Parse; 

print "ptmf2pcap: Convert HUAWEI PTMF Binary to PCAP/PLAINTEXT (alpha) \n\n";

my $filename = $ARGV[0];

if (@ARGV == 0 || ! $filename =~ /\.ptmf$/i || ! -e $filename  ) { 
	print "Error: PTMF file not found or invalid!\n"; 
	print "Usage: \n";
	print "       ./ptmf2pcap.pl {filename.ptmf} \n\n";
	exit();
}

my $target = $ARGV[0];
$target =~ s{\.[^.]+$}{};

# Sanitize and Shrink target
$target =~ tr/a-zA-Z0-9//dc;
if (length($target) > 20) { $target =~ s/.{20}\K.*//s; } 

# PCAP Writer destination
my $writer = Net::PcapWriter->new($target.'-ptmf.pcap');

system("rm -rf ./$target-ptmf.log");

print "Parsing & Converting records.... \n";

my $hexdata = `cat "$filename"`;

my $hexdata_pack = unpack "H*", $hexdata;

my @values = split('6d736730', $hexdata_pack); # Msg0

my $count = -1;
my $hdr;
my $from_ip = '';
my $to_ip = '';
my $from_port = 0;
my $to_port = 0;
my $ts;
my $command;
my $t_ms; my $t_ts;
my $t_dt; my $t_yr; my $t_tm;
my $timestamp=0;
my $fragments=0;
my $valen=0;
my $fcount=0;
my $proto=17;

foreach my $val (@values) {
    $count++;
    $valen = length($val);
    if ($count >= 1 && $valen > 194 ) {

    # print "## RECORD $count\n";
    # print "## LEN $len\n";
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
		$from_port = hex($from_port);
		$to_port =  substr "$hdr", 179,2;
		$to_port = "$to_port" .  substr "$hdr", 177,2;
		$to_port = hex($to_port);

		# Year
                $t_yr =  substr "$hdr", 47,4;
                $t_yr =  hex($t_yr);
                # Date
                $t_dt =  substr "$hdr", 51,4;
                $t_dt = join '-', unpack "C*", pack "H*", $t_dt;
		# Time chunk
                $t_tm =  substr "$hdr", 55,6;
                $t_tm = join ':', unpack "C*", pack "H*", $t_tm;
                # Milliseconds chunk
                $t_ms =  substr "$hdr", 63,8;
                $t_ms = hex($t_ms);
                # Assemble %H:%M:%S.
                $t_ts = $t_tm.".".$t_ms;
                # Assemble %Y-%m-%d %H:%M:%S.
                $t_ts = $t_yr."-".$t_dt." ".$t_ts;

		# print "$t_ts: $from_ip:$from_port -> $to_ip:$to_port \n";

		# UNIX Timestamp for PCAP
		$timestamp =  str2time($t_ts);


	}

    	if ($valen > 200 ) {
	    # Hex Message, stripped
	    $val =  substr $val, 194;

		# Check & Strip first pair
		my $check =  substr $val, 0, 2;
	        $check =~ s/(([0-9a-f][0-9a-f])+)/pack('H*', $1)/ie;
		# $check =~ s/[^[:ascii:]]//g;
		$check =~ s/\x{0001}//g;
		$check =~ tr/\x{0001}-\x{001f}//d;
		if ($check eq "" ) {
		    #print "[CHOP]";
		    $val =  substr $val, 2;
		} 

	    my $log = "$val";

	    # Convert to text
	    $log =~ s/(([0-9a-f][0-9a-f])+)/pack('H*', $1)/ie;

            my ($viaproto) = $log =~ /Via: SIP\/2\.0\/(.*) /g;
		#print "PROTO: $viaproto \n";

		# Remove non-ASCII
		# $log =~ s/[\x80-\xFF]//g;

	      my $decoder = guess_encoding($log);
	      # print "DECODER: $decoder \n";
	      # Check if printable, otherwise skip packet
	    if ( $decoder =~ /Encode::XS=SCALAR/ ) {
	      # if ( $log =~ /[[:alpha:]]/ ) { 

	      if (defined $from_ip && defined $to_ip) {

			    if (defined $viaproto && $viaproto eq "TCP") { 
					my $conn = $writer->tcp_conn($from_ip,$from_port,$to_ip,$to_port);
					$conn->write(0,$log,$timestamp);
			    }
			    else { 
					my $conn = $writer->udp_conn($from_ip,$from_port,$to_ip,$to_port);
					$conn->write(0,$log,$timestamp);
		    	    }

	        }	

		# Log to text
		my $filelog =  './'.$target.'-ptmf.log';
                        #my $filelog = '/tmp/siplog.log';
                        open(my $fh2, '>>', $filelog) or die "Could not open log file '$filename' $!";
                        print $fh2 "$t_ts: $from_ip:$from_port -> $to_ip:$to_port \n";
                        print $fh2 "$log\n\n";
                        close $fh2;


             } # else no decoder, hex

      }


    } else {
	# Initial Header w/ report date and other useless (?) info
        $ts =  substr $val, -32, 32;
        $ts =~ s/(([0-9a-f][0-9a-f])+)/pack('H*', $1)/ie;
	#print "\nREPORT DATE: $ts\n";
    }

}

system("ls -alF ./$target-ptmf.*");
print "\nDone!\n\n";

exit 0;
