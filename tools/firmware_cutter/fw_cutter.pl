# albi firmware file identifier/cutter
# part of https://github.com/jindroush/albituzka
# fw_cutter.pl input_file [switches]
# -save - save firmware internal files

use strict;
use Encode;
use utf8;
use Digest::MD5 qw( md5_hex );

my $save_files = 0;

my $in = "update.chp";
$in = shift @ARGV if( @ARGV );

while( @ARGV )
{
	my $sw = shift @ARGV;
	if( $sw =~ /-save/ )
	{
		$save_files = 1;
	}
	else
	{
		die "Unknown switch $sw";
	}
}

#load whole file in memory
open IN, $in or die "Can't open file '$in'";
my $buf;
binmode IN;
my $length = -s $in;
sysread( IN, $buf, $length );
close IN;

#checksum it
my $md5 = md5_hex( $buf );
print "input: $in\n";
printf( "md5: %s\n", $md5 );

#get 6 dwords from offset 0xa0
my @dw = unpack( "V*", substr( $buf, 0xa0, 6*4 ) );
my $b2b = shift @dw;
my $b2e = shift @dw;
my $b3b = shift @dw;
my $b3e = shift @dw;

#implicit first part
my $b1b = 0x400000;
my $b1e = $b2b;

printf( "1.bin [%08X-%08X] = %d\n", $b1b, $b1e, ( $b1e - $b1b ) * 2 );
printf( "2.bin [%08X-%08X] = %d\n", $b2b, $b2e, ( $b2e - $b2b ) * 2 );
printf( "3.bin [%08X-%08X] = %d\n", $b3b, $b3e, ( $b3e - $b3b ) * 2 );
printf "Computed length: %s\n", ( ($b3e-$b1b)*2 == $length )? "Ok!" : "mismatch!";
printf( "unk: %08X\n", shift @dw );
my $verptr = shift @dw;
printf( "pointer to version: %08X\n", $verptr );
my $str = decode( "utf-16le", substr( $buf, ($verptr-$b1b)*2, 0x32 ) );
printf( "ver: %s\n", $str );

#read chip type from offset 0x100
my $chip = pack( "C*", reverse unpack( "C*", substr( $buf, 0x100, 7 ) ) );
printf "chip: %s\n", $chip;



&extract_1bin();
&extract_2bin();
&extract_3bin();

sub extract_1bin()
{
	if( $save_files )
	{
		open OUT, ">:encoding(utf8)", "firm_1.txt" or die;
	}

	my $text_offsets = 0x638;
	my $i;
	for( $i = 0; $i <5000; $i++ )
	{
		my( $dw1, $dw2 ) = unpack( "VV", substr( $buf, $text_offsets + $i * 4, 8 ) );
	
		last if( $dw2 == 0 );
	
		#printf( "%08X [%08X-%08X] = %2X\n", $i*4, $dw1 + $text_offsets, $dw2 + $text_offsets, $dw2-$dw1 );
	
		if( $save_files )
		{
			my $data = substr( $buf, 0x638 + $dw1, $dw2 - $dw1 );
			my $str = decode( "utf-16le", $data );
			printf( OUT "%08X [%08X-%08X] = %2X  ", $i*4, $dw1, $dw2, $dw2-$dw1 );
			print OUT "$i\t$str\n";	
		}
	}

	if( $save_files )
	{
		close OUT;
	}
	print "1bin found $i song titles (?)\n";
}

sub extract_2bin()
{
	my @d;
	my $fptr = undef;
	my $b2bm = ( $b2b - 0x400000 ) * 2;
	my $ptr = $b2bm;

	REPT:
	my ( $f, $l ) = unpack( "VV", substr( $buf, $ptr, 8 ) );
	$f += $b2bm;
	$l += $b2bm;
	$ptr += 4;
	push @d, [$f,$l-$f];
	$fptr = $f if( ! defined $fptr );
	goto REPT if( $ptr < $fptr );
	
	my $cnt = 0;
	foreach my $ar ( @d )
	{
		my $f = $$ar[0];
		my $l = $$ar[1];

		if( $save_files )
		{	
			open OUT, ">" . sprintf( "2-%03d.mp3", $cnt ) or die;
			binmode OUT;
			print OUT substr( $buf, $f, $l );
			close OUT;
		}
		$cnt++;
	}
	print "2bin found ", scalar( @d ), " mp3s\n";
}

sub extract_3bin()
{
	my $b3bm = ( $b3b - 0x400000 ) * 2; 

	my @dws = unpack( "V*", substr( $buf, $b3bm + 0x30340, 3*4 ) );
	$dws[0] += $b3bm;
	$dws[1] += $b3bm;
	$dws[2] += $b3bm;

	#print join( "-", map( sprintf( "%08X", $_ ), @dws )), "<\n";

	my $cnt = 0;
	for( my $ptr = 0x30400+$b3bm; $ptr < 0x30500 + $b3bm; $ptr += 8 )
	{
		$cnt++;
		my ( $f, $l ) = unpack( "VV", substr( $buf, $ptr, 8 ) );
		next if( $f == 0x0 || $f == 0xFFFFFFFF );

		$f += $b3bm;

		if( $l && $save_files )
		{
			printf( "%d) %08X [%08X]\n", $cnt, $f, $f + $l );
        		open OUT, ">" . sprintf( "31_%03d.mp3", $cnt ) or die;
			binmode OUT;
			print OUT substr( $buf, $f, $l );
			close OUT;
		}
	}
	print "3bin/part 1 found $cnt mp3s\n";

	$cnt = 0;
	for( my $ptr = $dws[0]; $ptr < $dws[0]+0x100; $ptr += 8 )
	{
		my ( $f, $l ) = unpack( "VV", substr( $buf, $ptr, 8 ) );
		next if( $f == 0x0 || $f == 0xFFFFFFFF );
		$cnt++;
		if( $save_files )
		{
			printf( "%d) %08X/%08X\n", $cnt, $f, $l );
		}
	}
	print "3bin/part 2 found $cnt records\n";

	$cnt = 0;
	for( my $ptr = $dws[1]; $ptr < $dws[1]+0x500; $ptr += 8 )
	{
		my ( $f, $l ) = unpack( "VV", substr( $buf, $ptr, 8 ) );
		next if( $f == 0x0 || $f == 0xFFFFFFFF );

		$f += $b3bm;

		$cnt++;
		if( $l && $save_files )
		{
			printf( "%d) %08X [%08X]\n", $cnt, $f, $f + $l );
			open OUT, ">" . sprintf( "33_%03d.mp3", $cnt ) or die;
			binmode OUT;
			print OUT substr( $buf, $f, $l );
			close OUT;
		}
	}
	print "3bin/part 3 found $cnt mp3s\n";

	$cnt = 0;
	for( my $ptr = $dws[2]; $ptr < $dws[2]+0x100; $ptr += 8 )
	{
		my ( $f, $l ) = unpack( "VV", substr( $buf, $ptr, 8 ) );
		next if( $f == 0x0 || $f == 0xFFFFFFFF );
		#printf( "%08X\n", $f );

		$f += $b3bm;
		next if( $l == 0 );

		$cnt++;

		my $str = substr( $buf, $f, $l * 2 );
		$str = decode( "utf16le", $str );
		if( $save_files )
		{
			printf( "%d) %08X [%08X] %s\n", $cnt, $f, $f + $l, $str );
		}
	
	}
	print "3bin/part 4 found $cnt strings\n";
}
