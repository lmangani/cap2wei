#!/usr/bin/perl
# 
# App: Cap2Wei
# Version: 0.1b (06/09/2014)
# Description: Script to convert HUAWEI's TMF text trace to standard PCAP + Clear LOG
# Hacked together while re-watching "Boris 3" by L. Mangani & C.Mangani 

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

use strict;
use warnings;
use IPC::Cmd qw[can_run run];

print "Cap2Wei: Convert HUAWEI IMS Mystery text traces to PCAP + Clear LOG\n\n";

my $full_path = can_run('text2pcap') or warn 'text2pcap is not installed! Please install wireshark \n';
$full_path = can_run('mergecap') or warn 'mergecap is not installed! Please install wireshark \n';
$full_path = can_run('bittwiste') or warn 'bittwiste is not installed! Please install from http://bittwist.sourceforge.net \n';

my $filename = $ARGV[0];

if (! -e $filename || @ARGV == 0 ) { 
	print "oops, source file not found!\n"; usage(); 
	print "Usage: \n";
	print "       ./cap2wei.pl {filename} \n\n";
	exit();
}

my $target = $ARGV[0];
$target =~ s{\.[^.]+$}{};
my $tmp = "/tmp/$target-tmp";

open(my $fh => $filename) || die "Cannot open $filename: $!";

my $count = 0;
my $ts;
my $from_ip;
my $to_ip;
my $from_port;
my $to_port;
my $command;
my $last;
my $siplog;

system("mkdir $tmp");
	print "Converting trace to pcap....";

while(my $line = <$fh>) {
	if ($line =~ /TimeStamp/) {
		$line =  substr $line, 25;
		$ts = $line;
	} elsif ($line =~ /Message Type/) {
		# MS Hack to order 100 Trying in sequence w/ Invites
		$line =  substr $line, 25;
		# if ($line =~ /100 T/ ) { 
		#   $ts =~ s/.$/9/;
		# }
	} elsif ($line =~ /Source Add/) {
		$line =  substr $line, 25;
		$line =~ s/\R//g;
		$from_ip = "$line";
	} elsif ($line =~ /Destination Add/) {
		$line =  substr $line, 25;
		$line =~ s/\R//g;
		$to_ip = "$line";
	} elsif ($line =~ /Source Port/) {
		$line =  substr $line, 25;
		$line =~ s/\R//g;
		$from_port = "$line";
	} elsif ($line =~ /Destination Port/) {
		$line =  substr $line, 25;
		$line =~ s/\R//g;
		$to_port = "$line";
	} elsif ($line =~ /Hex Message/) {
		$count++;
		#print "# Packet $count\n";
		#print "$ts\n";

		# Strip heading
		$line =  substr $line, 25;
		# Convert to ASCII for siplog
		$siplog = "$line";
		# Reformat (old)
		$siplog =~ tr/ //ds;;
		$siplog =~ s/\(..\)/\$1 /g;
		# Write to siplog
		$siplog =~ s/(([0-9a-f][0-9a-f])+)/pack('H*', $1)/ie;

		#if ( -T "$siplog" ) {
			my $filelog =  $tmp.'/'.$target.'.log';
			#my $filelog = '/tmp/siplog.log';
			open(my $fh2, '>>', $filelog) or die "Could not open log file '$filename' $!";
			print $fh2 "$ts$from_ip:$from_port -> $to_ip:$to_port\n$siplog";
			print $fh2 $siplog;
			close $fh2;
		#}

		# Row Prefix for text2pcap
		$line =~ s/^/00000 /;

		# Inject Timestamp
		$line = $ts.$line;

		# Write to temp file and send to text2cap
			my $filename = $tmp.'/p'.$count.'.txt';
			open(my $fh, '>', $filename) or die "Could not open file '$filename' $!";
			print $fh $line;
			close $fh;

		$command = "text2pcap -q -u $from_port,$to_port -t '%Y-%m-%d %H:%M:%S.' -i 17 $tmp/p$count.txt $tmp/p$count.pcap";
		system($command);

		if ($from_port > 1) {
			system("bittwiste -I $tmp/p$count.pcap -O $tmp/p$count-2.pcap -T ip -s $from_ip > /dev/null 2>&1");
			system("bittwiste -I $tmp/p$count-2.pcap -O $tmp/p$count-3.pcap -T ip -d $to_ip > /dev/null 2>&1");
			system("rm -rf $tmp/p$count.pcap");
			system("rm -rf $tmp/p$count-2.pcap");
		}
	}
}

close($fh);

print "Done!\n";

# Mergecap of all fragments (needs timestamp!!!)
	print "Merging pcaps....";
	system("mergecap -w $target.pcap $tmp/*.pcap");
	system("mv $tmp/$target.log ./");
# Clean up
	system("rm -rf $tmp");
	print "Done!\n";

print "Original: $filename \n";
print "PCAP    : $target.pcap \n";
print "TEXT-Log: $target.log \n\n";

exit 0;
