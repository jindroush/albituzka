# albi bnl file decryptor/disassembler, works also for some arabic downloads
# written by jindroush, published under MPL license
# part of https://github.com/jindroush/albituzka
#
# bnl_dis.pl input_file [switches]
# -extract - extracts mp3 files to current directory
# -bitrate - computes mp3 files bitrate
# -nosave - does not output any files

# all files output to current directory:
# *.mp3 - decrypted mp3 files
# rbuf.dat - copy of input file, with read data overwritten by # character. It's used for coverage testing
# bnl.json - output of BNL data structures. This file is consumed by bnl_creator.pl

# everything is guessed from downloadable files
# 11.01.2022 jindroush	first so-so version
# 08.02.2022 jindroush	decoding of type4 quiz question
# 14.02.2022 jindroush	changed all json constant to hex, also exporting type4 quiz
# 15.02.2022 jindroush	changed json varnames to make more sense
# 20.02.2022 jindroush	changed oid converter to OID2.0
# 12.01.2023 jindroush	some files can have oid table on other offset than 0x200 (wonder if that's Albi pen compatible?)

use strict;
use YAML;
use MP3::Info;

my @oid_tbl_int2raw;
&oid_converter_init();

#global pars
my $infile = "in.bnl";
my $extract_mp3 = 0;
my $extract_mp3_br = 0;
my $save = 1;

#globals
my %BNL;
my $lo_rbuf = 1<<32 - 1;
my $hi_rbuf = 0;
my $buf;
my $rbuf;

#cmdline processing
while( @ARGV )
{
	my $s = shift @ARGV;

	if( $s =~ /^\-{1,2}(.+)$/ )
	{
		my $sw = lc $1;
		if( $sw eq "extract" )
		{
			$extract_mp3 = 1;
		}
		elsif( $sw eq "bitrate" )
		{
			$extract_mp3_br = 1;
		}
		elsif( $sw eq "nosave" )
		{
			$extract_mp3 = 0;
			$save = 0;
		}		
	}
	else
	{
		$infile = $s;
	}
}

open IN, $infile or die;
binmode IN;
my $flen = -s $infile;
sysread( IN, $rbuf, $flen );
sysseek( IN, 0, 0 );

printf "file: $infile\n";
printf "len: %08X\n", $flen;

print "header:\n";
sysseek( IN, 0, 0 );
sysread( IN, $buf, 80 * 4 );
&mark_rbuf( 80 * 4 );
my @dws = unpack( "V*", $buf );
my $dkey = shift @dws;
printf "dkey: %08X\n", $dkey;
$BNL{header}{encryption}{ header_key } = sprintf( "0x%08X", $dkey );
my $oid_table_ptr = &get_ptr_value( shift @dws, $dkey );
printf "end of header/oid table ptr: %08X\n", $oid_table_ptr;

#removed the check
#die sprintf( "Oid table pointing to 0x%X, expecting 0x200?!", $oid_table_ptr ) if( $oid_table_ptr != 0x200 );
die sprintf( "Oid table pointing to 0x%X, expecting multiples of 0x200", $oid_table_ptr ) if( !$oid_table_ptr || ( $oid_table_ptr % 0x200 ) );

#table of pointers of media files
my $mtbl_ptr = &get_ptr_value( shift @dws, $dkey );
printf "media table: %08X\n", $mtbl_ptr;

my $ptr_start_button_1st_read_media = &get_ptr_value( shift @dws, $dkey );
my $ptr_start_button_2nd_read_media = &get_ptr_value( shift @dws, $dkey );

my $unk_tbl_ptr5 = &get_ptr_value( shift @dws, $dkey );
my ( $oid_min, $oid_max, $mediafiles_cnt, $w3 ) = unpack( "v*", pack( "V*", (shift @dws, shift @dws ) ) );
printf "min file oid: %04X\n", $oid_min; #this is min file oid, we've seen always zero here
printf "max file oid: %04X\n", $oid_max;
printf "media files cnt: %d\n", $mediafiles_cnt;
printf "w07b: %04X\n", $w3;
my $unk_tbl_ptr8 = &get_ptr_value( shift @dws, $dkey );
my $ptr_book_mode_read_media = &get_ptr_value( shift @dws, $dkey );

printf "dw0A: %08X\n", &get_ptr_value( shift @dws, $dkey );
my $book_modes = shift @dws;
printf "book modes: %08X\n", $book_modes;
printf "dw0C: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw0D: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw0E: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw0F: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw10: %08X\n", &get_ptr_value( shift @dws, $dkey );

printf "start_button_1st_read: %08X (dw3)\n", $ptr_start_button_1st_read_media;
&allmedia_tbl( $ptr_start_button_1st_read_media, $BNL{header}, "start_button_1st_read" );
printf "start_button_2nd_read: %08X (dw4)\n", $ptr_start_button_2nd_read_media;
&allmedia_tbl( $ptr_start_button_2nd_read_media, $BNL{header}, "start_button_2nd_read" ) if( $ptr_start_button_2nd_read_media != 0xFFFFFFFF );
printf "dw05: %08X\n", $unk_tbl_ptr5;
&allmedia_tbl( $unk_tbl_ptr5, $BNL{header}, "unk_tbl_ptr5" ) if( $unk_tbl_ptr5 != 0xFFFFFFFF );
printf "dw08: %08X\n", $unk_tbl_ptr8;
&allmedia_tbl( $unk_tbl_ptr8, $BNL{header}, "unk_tbl_ptr8" ) if( $unk_tbl_ptr8 != 0xFFFFFFFF );
printf "book_mode_read: %08X (dw9)\n", $ptr_book_mode_read_media;
&allmedia_tbl( $ptr_book_mode_read_media, $BNL{header}, "book_mode_read" );


my $ptr_quiz_table = &get_ptr_value( shift @dws, $dkey );
#points to list of file pointers
$BNL{quiz} = {};
$BNL{quiz}{quizes} = [];
printf "quiz_table: %08X\n", $ptr_quiz_table;
&quiz_tbl( $ptr_quiz_table );

#points to table of w-len, and w-numbers
my $ptr_quiz_pos1 = &get_ptr_value( shift @dws, $dkey );
printf "quiz_pos1: %08X\n", $ptr_quiz_pos1;
&oid_tbl( $ptr_quiz_pos1, $BNL{quiz}, "quiz_pos1" );

#points to table of w-len, and w-numbers
my $ptr_quiz_pos2 = &get_ptr_value( shift @dws, $dkey );
printf "quiz_pos2: %08X\n", $ptr_quiz_pos2;
&oid_tbl( $ptr_quiz_pos2, $BNL{quiz}, "quiz_pos2" );

#points to table of w-len, and w-numbers
my $ptr_quiz_neg1 = &get_ptr_value( shift @dws, $dkey );
printf "quiz_neg1: %08X\n", $ptr_quiz_neg1;
&oid_tbl( $ptr_quiz_neg1, $BNL{quiz}, "quiz_neg1" );

#points to table of w-len, and w-numbers
my $ptr_quiz_neg2 = &get_ptr_value( shift @dws, $dkey );
printf "quiz_neg2: %08X\n", $ptr_quiz_neg2;
&oid_tbl( $ptr_quiz_neg2, $BNL{quiz}, "quiz_neg2" );

#points to table of w-len, and w-numbers
my $unk_tbl_ptr_16 = &get_ptr_value( shift @dws, $dkey );
printf "unk_tbl_ptr_16: %08X\n", $unk_tbl_ptr_16;
&oid_tbl( $unk_tbl_ptr_16, $BNL{header}, "unk_tbl_ptr_16" );

my $book_id = shift @dws;
printf "book_id: %08X [%04X]\n", $book_id, &oid2rawoid( $book_id ) ;
$BNL{header}{ book_id } = sprintf( "0x%04X", $book_id );


my $unk_tbl_ptr_18 = &get_ptr_value( shift @dws, $dkey );
printf "dw18: %08X\n", $unk_tbl_ptr_18;
&allmedia_tbl( $unk_tbl_ptr_18, $BNL{header}, "unk_tbl_ptr_18" ) if( $unk_tbl_ptr_18 != 0xFFFFFFFF );

my $unk_tbl_ptr_19 = &get_ptr_value( shift @dws, $dkey );
printf "dw19: %08X\n", $unk_tbl_ptr_19;
&allmedia_tbl( $unk_tbl_ptr_19, $BNL{header}, "unk_tbl_ptr_19" ) if( $unk_tbl_ptr_19 != 0xFFFFFFFF );

my $unk_tbl_ptr_1a = &get_ptr_value( shift @dws, $dkey );
printf "dw1A: %08X\n", $unk_tbl_ptr_1a;
&allmedia_tbl( $unk_tbl_ptr_1a, $BNL{header}, "unk_tbl_ptr_1a" ) if( $unk_tbl_ptr_1a != 0xFFFFFFFF );

my $unk_tbl_ptr_1b = &get_ptr_value( shift @dws, $dkey );
printf "dw1B: %08X\n", $unk_tbl_ptr_1b;
&allmedia_tbl( $unk_tbl_ptr_1b, $BNL{header}, "unk_tbl_ptr_1b" ) if( $unk_tbl_ptr_1b != 0xFFFFFFFF );

my $unk_tbl_ptr_1c = &get_ptr_value( shift @dws, $dkey );
printf "dw1C: %08X\n", $unk_tbl_ptr_1c;
&allmedia_tbl( $unk_tbl_ptr_1c, $BNL{header}, "unk_tbl_ptr_1c" ) if( $unk_tbl_ptr_1c != 0xFFFFFFFF );

my $unk_tbl_ptr_1d = &get_ptr_value( shift @dws, $dkey );
printf "dw1D: %08X\n", $unk_tbl_ptr_1d;
&allmedia_tbl( $unk_tbl_ptr_1d, $BNL{header}, "unk_tbl_ptr_1d" ) if( $unk_tbl_ptr_1d != 0xFFFFFFFF );

my $unk_tbl_ptr_1e = &get_ptr_value( shift @dws, $dkey );
printf "dw1E: %08X\n", $unk_tbl_ptr_1e;
&allmedia_tbl( $unk_tbl_ptr_1e, $BNL{header}, "unk_tbl_ptr_1e" ) if( $unk_tbl_ptr_1e != 0xFFFFFFFF );

my $unk_tbl_ptr_1f = &get_ptr_value( shift @dws, $dkey );
printf "dw1F: %08X\n", $unk_tbl_ptr_1f;
&allmedia_tbl( $unk_tbl_ptr_1f, $BNL{header}, "unk_tbl_ptr_1f" ) if( $unk_tbl_ptr_1f != 0xFFFFFFFF );

my $unk_tbl_ptr_20 = &get_ptr_value( shift @dws, $dkey );
printf "dw20: %08X\n", $unk_tbl_ptr_20;
&allmedia_tbl( $unk_tbl_ptr_20, $BNL{header}, "unk_tbl_ptr_20" ) if( $unk_tbl_ptr_20 != 0xFFFFFFFF );

my $unk_tbl_ptr_21 = &get_ptr_value( shift @dws, $dkey );
printf "dw21: %08X\n", $unk_tbl_ptr_21;
&allmedia_tbl( $unk_tbl_ptr_21, $BNL{header}, "unk_tbl_ptr_21" ) if( $unk_tbl_ptr_21 != 0xFFFFFFFF );

my $unk_tbl_ptr_22 = &get_ptr_value( shift @dws, $dkey );
printf "dw22: %08X\n", $unk_tbl_ptr_22;
&allmedia_tbl( $unk_tbl_ptr_22, $BNL{header}, "unk_tbl_ptr_22" ) if( $unk_tbl_ptr_22 != 0xFFFFFFFF );

my $unk_tbl_ptr_23 = &get_ptr_value( shift @dws, $dkey );
printf "dw23: %08X\n", $unk_tbl_ptr_23;
&allmedia_tbl( $unk_tbl_ptr_23, $BNL{header}, "unk_tbl_ptr_23" ) if( $unk_tbl_ptr_23 != 0xFFFFFFFF );

my $unk_tbl_ptr_24 = &get_ptr_value( shift @dws, $dkey );
printf "dw24: %08X\n", $unk_tbl_ptr_24;
&allmedia_tbl( $unk_tbl_ptr_24, $BNL{header}, "unk_tbl_ptr_24" ) if( $unk_tbl_ptr_24 != 0xFFFFFFFF );

my $unk_tbl_ptr_25 = &get_ptr_value( shift @dws, $dkey );
printf "dw25: %08X\n", $unk_tbl_ptr_25;
&allmedia_tbl( $unk_tbl_ptr_25, $BNL{header}, "unk_tbl_ptr_25" ) if( $unk_tbl_ptr_25 != 0xFFFFFFFF );

my $unk_tbl_ptr_26 = &get_ptr_value( shift @dws, $dkey );
printf "dw26: %08X\n", $unk_tbl_ptr_26;
&allmedia_tbl( $unk_tbl_ptr_26, $BNL{header}, "unk_tbl_ptr_26" ) if( $unk_tbl_ptr_26 != 0xFFFFFFFF );


my $unk_tbl_ptr_27 = &get_ptr_value( shift @dws, $dkey );
printf "unk_tbl_ptr_27: %08X\n", $unk_tbl_ptr_27;
&oid_tbl( $unk_tbl_ptr_27, $BNL{header}, "unk_tbl_ptr_27" );
my $unk_tbl_ptr_28 = &get_ptr_value( shift @dws, $dkey );
printf "unk_tbl_ptr_28: %08X\n", $unk_tbl_ptr_28;
&oid_tbl( $unk_tbl_ptr_28, $BNL{header}, "unk_tbl_ptr_28" );
my $unk_tbl_ptr_29 = &get_ptr_value( shift @dws, $dkey );
printf "unk_tbl_ptr_29: %08X\n", $unk_tbl_ptr_29;
&oid_tbl( $unk_tbl_ptr_29, $BNL{header}, "unk_tbl_ptr_29" );
my $ptr_quiz_results = &get_ptr_value( shift @dws, $dkey );
printf "quiz_results: %08X\n", $ptr_quiz_results;
&oid_tbl( $ptr_quiz_results, $BNL{quiz}, "quiz_results" );

printf "dw2B: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw2C: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw2D: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw2E: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw2F: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw30: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw31: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw32: %08X\n", &get_ptr_value( shift @dws, $dkey );

my $unk_tbl_ptr_33 = &get_ptr_value( shift @dws, $dkey );
printf "dw33: %08X\n", $unk_tbl_ptr_33;
&allmedia_tbl( $unk_tbl_ptr_33, $BNL{header}, "unk_tbl_ptr_33" ) if( $unk_tbl_ptr_33 != 0xFFFFFFFF );

my $unk_tbl_ptr_34 = &get_ptr_value( shift @dws, $dkey );
printf "dw34: %08X\n", $unk_tbl_ptr_34;
&allmedia_tbl( $unk_tbl_ptr_34, $BNL{header}, "unk_tbl_ptr_34" ) if( $unk_tbl_ptr_34 != 0xFFFFFFFF );

my $unk_tbl_ptr_35 = &get_ptr_value( shift @dws, $dkey );
printf "dw35: %08X\n", $unk_tbl_ptr_35;
&allmedia_tbl( $unk_tbl_ptr_35, $BNL{header}, "unk_tbl_ptr_35" ) if( $unk_tbl_ptr_35 != 0xFFFFFFFF );

my $unk_tbl_ptr_36 = &get_ptr_value( shift @dws, $dkey );
printf "dw36: %08X\n", $unk_tbl_ptr_36;
&allmedia_tbl( $unk_tbl_ptr_36, $BNL{header}, "unk_tbl_ptr_36" ) if( $unk_tbl_ptr_36 != 0xFFFFFFFF );

my $unk_tbl_ptr_37 = &get_ptr_value( shift @dws, $dkey );
printf "dw37: %08X\n", $unk_tbl_ptr_37;
&allmedia_tbl( $unk_tbl_ptr_37, $BNL{header}, "unk_tbl_ptr_37" ) if( $unk_tbl_ptr_37 != 0xFFFFFFFF );

my $unk_tbl_ptr_38 = &get_ptr_value( shift @dws, $dkey );
printf "dw38: %08X\n", $unk_tbl_ptr_38;
&allmedia_tbl( $unk_tbl_ptr_38, $BNL{header}, "unk_tbl_ptr_38" ) if( $unk_tbl_ptr_38 != 0xFFFFFFFF );

my $unk_tbl_ptr_39 = &get_ptr_value( shift @dws, $dkey );
printf "dw39: %08X\n", $unk_tbl_ptr_39;
&allmedia_tbl( $unk_tbl_ptr_39, $BNL{header}, "unk_tbl_ptr_39" ) if( $unk_tbl_ptr_39 != 0xFFFFFFFF );

my $unk_tbl_ptr_3a = &get_ptr_value( shift @dws, $dkey );
printf "dw3A: %08X\n", $unk_tbl_ptr_3a;
&allmedia_tbl( $unk_tbl_ptr_3a, $BNL{header}, "unk_tbl_ptr_3A" ) if( $unk_tbl_ptr_3a != 0xFFFFFFFF );

my $unk_tbl_ptr_3b = &get_ptr_value( shift @dws, $dkey );
printf "dw3B: %08X\n", $unk_tbl_ptr_3b;
&allmedia_tbl( $unk_tbl_ptr_3b, $BNL{header}, "unk_tbl_ptr_3B" ) if( $unk_tbl_ptr_3b != 0xFFFFFFFF );

printf "dw3C: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw3D: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw3E: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw3F: %08X\n", &get_ptr_value( shift @dws, $dkey );
my $unk_tbl_ptr_40 = &get_ptr_value( shift @dws, $dkey );
printf "dw40: %08X\n", $unk_tbl_ptr_40;
&allmedia_tbl( $unk_tbl_ptr_40, $BNL{header}, "unk_tbl_ptr_40" ) if( $unk_tbl_ptr_40 != 0xFFFFFFFF );
printf "dw41: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw42: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw43: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw44: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw45: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw46: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw47: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw48: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw49: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw4A: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw4B: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw4C: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw4D: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw4E: %08X\n", &get_ptr_value( shift @dws, $dkey );
printf "dw4F: %08X\n", &get_ptr_value( shift @dws, $dkey );


#header mostly done, now do the key magic
my $k3 = ( $dkey >> 24 ) & 0xFF;

sysseek( IN, 0x140, 0 );
sysread( IN, $buf, 20 );
&mark_rbuf( 20 );
my @pre_key = unpack( "VC*", $buf );
my $dw = shift @pre_key;

#we know for sure that first dword is needed on real hardware for decryption
#since we don't understand how the key derivation really works
#we'll need to use this as an hardcoded value
printf( "key modifier: %02X\n", $k3 );
$BNL{header}{encryption}{ prekey_dw } = sprintf( "0x%08X", $dw );
$BNL{header}{encryption}{ prekey } = [ map( { sprintf( "0x%02X", $_ ) } @pre_key )];

printf( "Pre-key_dw: %08X\n", $dw );
printf( "Pre-key: " );
foreach ( @pre_key )
{
	printf( "%02X ", $_ );
	$_ = ( $_ + $k3 ) & 0xFF;
}
print "\n";
printf( "Realkey: " );
foreach ( @pre_key )
{
	printf( "%02X ", $_ );
}
print "\n";
&media_tbl( $mtbl_ptr );

printf "end of header processing\n\n";


print "OID2media table start\n";
sysseek( IN, $oid_table_ptr, 0 );
sysread( IN, $buf, ( $oid_max - $oid_min + 1 ) * 4 );
&mark_rbuf( ( $oid_max - $oid_min + 1 ) * 4 );
my @ptrs = unpack( "V*", $buf );
$BNL{oids} = {};

#these two variables are only for OID mapping (which is not needed anymore, as we have decoded the OCF table)
my %OIDS;
my $o_st = undef;

my $cnt = $oid_min;
while( @ptrs )
{
	my $ptr = shift @ptrs;

	if( $ptr != 0xFFFFFFFF )
	{
		printf( "file oid-%04X [paper:%04X]) %08X %08X\n", $cnt, &oid2rawoid( $cnt ), $oid_table_ptr + 4*($cnt-$oid_min), $ptr );
		&allmedia_tbl( $ptr, $BNL{ oids }, sprintf( "oid_x%04X", $cnt ) );

		$o_st = $cnt if( !defined $o_st );
	}
	else
	{
		if( defined $o_st )
		{
			$OIDS{ sprintf( "%04X-%04X", $o_st, $cnt - 1 ) } = 1;
		}
		$o_st = undef;
	}
	$cnt++;
}
if( defined $o_st )
{
	$OIDS{ sprintf( "%04X-%04X", $o_st, $cnt - 1 ) } = 1;
}




if( $save )
{
	#dump modified rbuf
	open OUT, ">rbuf.dat" or die;
	binmode OUT;
	print OUT $rbuf;
	close OUT;
}

print "oid-spans:[" . join( ",", sort keys %OIDS ) . "]\n";
&verify_rbuf();

if( $save )
{
	#dump yaml if needed
	open OUT, ">bnl.yaml" or die;
	print OUT YAML::Dump($BNL{header},$BNL{quiz},$BNL{oids});
	close OUT;

}

#this function simply xors pointer with dkey value or returns 'nothing' for 'nothing'
sub get_ptr_value()
{
	my $val = $_[0];
	my $dkey = $_[1];

	return $val if( $val eq 0 || $val eq 0xFFFFFFFF );

	return $val ^ $dkey;
}

#reads media table and, optionally, extracts decrypted files
sub media_tbl()
{
	my $ptr = $_[0];
	my $cnt = 0;

	my %BRS;

	my @key = &keygen( \@pre_key );
	my $key_length = scalar @key;

	my $fptr;

	for(;;)
	{
		sysseek( IN, $ptr, 0 );
		sysread( IN, $buf, 8 );
		&mark_rbuf( 8 );
		my( $d1, $d2 ) = unpack( "VV", $buf );
		$fptr = $d1 unless( defined $fptr );

		#this basically checks for the end of media table
		#because the number of media files is not stored anywhere (the one in the header is usually shorter)
		#we check if there is end-of-table in form of zero-padding or if the end of the table is past start of first mp3 file
		if( $d2 == 0 || $ptr+4 >= $fptr )
		{
			printf( "\textracted 0000 to %04d media files\n", $cnt - 1);
	
			if( scalar keys %BRS )
			{
				#outputting the most common bitrate combination
				my $fk = ( sort { $BRS{$b} <=> $BRS{$a} } keys %BRS )[0];
				my $perc = int( $BRS{$fk} * 100 / $cnt );
				print "\tmp3s_br: $fk: $perc%\n";
			}
			return;
		}

		#printf( "\t%04d) %08X-%08X (%08X)\n", $cnt, $d1, $d2, $d2-$d1 );

		my $ofn = sprintf( "media_%04d.mp3", $cnt );

		my $extract_file = 0;
		my $remove_file = 0;

		if( $extract_mp3_br )
		{
			$extract_file = 1;
			$remove_file = 1;
		}

		#order is important, remove gets overwritten on purpose here
		if( $extract_mp3 )
		{
			$extract_file = 1;
			$remove_file = 0;
			$extract_mp3_br = 1;
		}
	
		#if there is any extracted file with nonzero len, don't extract
		if( -s $ofn )
		{
			$extract_file = 0;
			$remove_file = 0;
		}
	
		if( $extract_file )
		{
			my $buf;
			sysseek( IN, $d1, 0 );
			sysread( IN, $buf, $d2 - $d1 );
			&mark_rbuf( $d2-$d1 );
			&decrypt_mem( \$buf, \@key );
			open OUT, ">" . $ofn or die;
			binmode OUT;
			print OUT $buf;
			close OUT;
		}
		else
		{
			#nothing just marks rbuf data
			sysseek( IN, $d2, 0 );
			&mark_rbuf( $d2-$d1 );
	
		}
	
		if( $extract_mp3_br )
		{
			my $hr = get_mp3info( $ofn );
			#BITRATE: 96
			#COPYRIGHT: 0
			#FRAMES: 299
			#FRAME_LENGTH: 314
			#FREQUENCY: 44.1
			#LAYER: 3
			#MM: 0
			#MODE: 3
			#MS: 835.166666666667
			#OFFSET: 45
			#PADDING: 0
			#SECS: 7.83516666666667
			#SIZE: 94022
			#SS: 7
			#STEREO: 0
			#TIME: 00:07
			#VBR: 0
			#VERSION: 1
			my $str = sprintf( "%skbps %s %s/%skHz", $$hr{BITRATE}, $$hr{VBR}? "VBR" : "CBR", $$hr{STEREO} ? "stereo":"mono", $$hr{FREQUENCY} );
			#print "\t$ofn\t$str\n";
			$BRS{ $str }++;
		}
	
		if( $remove_file )
		{
			unlink $ofn;
		}
	
		$cnt++;
		$ptr += 4;
	}
}

sub allmedia_tbl()
{
	my $ptr = $_[0];
	my $hr_bnl = $_[1];
	my $bnl_key = $_[2];

	sysseek( IN, $ptr, 0 );
	my $lcnt = 0;

	for(;;)
	{
		sysread( IN, $buf, 2 );
		&mark_rbuf( 2 );
		$ptr += 2;
		my $cnt = unpack( "v", $buf );
		if( $cnt == 0 )
		{
			print "\tcnt: 0\n";
		}
		else
		{
			sysread( IN, $buf, $cnt * 2 );
			&mark_rbuf( $cnt * 2 );
			$ptr += $cnt * 2;
			my @vals = unpack( "v*", $buf );
			print "\tcnt: $cnt, media:[", join( ", ", map( sprintf( "%04d", $_ ), @vals ) ), "]\n";
			$$hr_bnl{ $bnl_key }{ "mode_" . $lcnt } = [map( sprintf( "media_%04d.mp3", $_), @vals)];
		}
		$lcnt++;
		last if( $lcnt >= $book_modes );
	}
}

sub oid_tbl()
{
	my $ptr = $_[0];
	my $hr_bnl = $_[1];
	my $bnl_key = $_[2];

	sysseek( IN, $ptr, 0 );
	my $buf;
	sysread( IN, $buf, 2 );
	&mark_rbuf( 2 );
	my $cnt = unpack( "v", $buf );
	sysread( IN, $buf, $cnt * 2 );
	&mark_rbuf( $cnt * 2 );
	my @vals = unpack( "v*", $buf );
	print "\tcnt: $cnt, oids:[", join( ", ", map( sprintf( "0x%04X", $_ ), @vals ) ), "]\n";
	$$hr_bnl{$bnl_key} = [map( sprintf( "oid_x%04X", $_), @vals)];
}

sub quiz_tbl()
{
	my $ptr = $_[0];
	my $buf;
	my $first_ptr = undef;

	my $cnt = 0;
	for(;;)
	{
		sysseek( IN, $ptr, 0 );
		sysread( IN, $buf, 4 );
		&mark_rbuf( 4 );
		my $dptr = unpack( "V", $buf );

		printf( "\tquiz %04X) ptr/%08X\n", $cnt+100, $dptr );
		&quiz_one_quiz( $dptr );

		$first_ptr = $dptr if( ! defined $first_ptr );

		$ptr += 4;
		$cnt++;

		#this works on assumption that first pointer points exactly after last pointer in the quiz table
		#because if I have loaded the correct book, I'd never get higher quiz OID than the length of the page
		#but, what would happen if I have book with 6 quizes and then I touch quiz 7 from other book?
		last if( defined $first_ptr && $ptr >= $first_ptr );
	}
}

sub quiz_one_quiz()
{
	my $ptr = $_[0];
	sysseek( IN, $ptr, 0 );
	my $buf;
	sysread( IN, $buf, 5 * 2 );
	&mark_rbuf( 5*2 );
	my( $q_type, $q_cnt, $q_asked, $q_unk, $q_oid ) = unpack( "v*", $buf );
	printf( "\t\tqtype:%04X cnt:%04X questions:%04X unk:%04X quiz_intro_oid: %04X\n", $q_type, $q_cnt, $q_asked, $q_unk, $q_oid );

	my %ONE_QUIZ;
	$ONE_QUIZ{ q_type } = sprintf( "0x%04X", $q_type );
	$ONE_QUIZ{ q_asked } = sprintf( "0x%04X", $q_asked );
	$ONE_QUIZ{ q_unk } = sprintf( "0x%04X", $q_unk );
	$ONE_QUIZ{ q_oid } = sprintf( "oid_x%04X", $q_oid );

	#die if( $q_type != 0 );
	#die if( $w3 != 0 );

	my @quiz_questions;
	
	sysread( IN, $buf, 4 * $q_cnt );
	&mark_rbuf( 4 * $q_cnt );
	my @ptrs = unpack( "V*", $buf );

	foreach $ptr ( @ptrs )
	{
		printf( "\t\t\tptr/%08X: ", $ptr );
		sysseek( IN, $ptr, 0 );

		#explicit handling of quiz type 4
		#this should be 'special handling' of quiz with less questions than default
		if( $q_type == 4 )
		{
			sysread( IN, $buf, 8 );
			&mark_rbuf( 8 );

			my( $q4_oid, $q4_unk1, $q4_unk2, $q4_unk3 ) = unpack( "v*", $buf );
			printf( "quiz_question4 oid:%04X unk1:%04X unk2:%04X unk3:%04X\n", $q4_oid, $q4_unk1, $q4_unk2, $q4_unk3 );
			
			my %Q4;

			for( my $i = 0; $i < 8; $i++ )
			{
				sysread( IN, $buf, 2 );
				&mark_rbuf(2);
				my $cnt = unpack( "v", $buf );
				sysread( IN, $buf, 2*$cnt );
				&mark_rbuf( 2*$cnt );
				my @oids = unpack( "v*", $buf );
				my $ia = $i;
				$ia = "good_reply_oids" if( $ia == 0 );
				$ia = "unknown_oids   " if( $ia == 1 );
				$ia = "good_reply_snd1" if( $ia == 2 );
				$ia = "good_reply_snd2" if( $ia == 3 );
				$ia = "bad_reply_snd1 " if( $ia == 4 );
				$ia = "bad_reply_snd2 " if( $ia == 5 );
				$ia = "final_good     " if( $ia == 6 );
				$ia = "final_bad      " if( $ia == 7 );

				printf( "\t\t\t\t%s oids:[%s]\n", $ia, join( ", ", map( sprintf( "oid_x%04X", $_ ), @oids ))); 

				my $kname = "q4_" . $ia;
				$kname =~ s/\s+$//;
				$Q4{ $kname } = [ map(sprintf("oid_x%04X",$_), @oids )] 

			}
			push @quiz_questions, { q4_oid => sprintf("oid_x%04X", $q4_oid ), q4_unk1 => sprintf( "0x%04X", $q4_unk1 ), q4_unk2 => sprintf( "0x%04X", $q4_unk2 ), q4_unk3 => sprintf( "0x%04X", $q4_unk3 ), %Q4 };
       		}	
		else
		{
			#implicitely all quiz types are handled here (but only type 0 should actually be)
			#if( $q_type == 0 ) -> we won't check now
			sysread( IN, $buf, 6 );
			&mark_rbuf( 6 );
			my( $q1_unk, $q1_oid, $oid_cnt ) = unpack( "v*", $buf );
			printf( "quiz_question0 unk:%04X oid_question:%04X replies_oids:[", $q1_unk, $q1_oid );
			sysread( IN, $buf, 2* $oid_cnt );
			&mark_rbuf( 2 * $oid_cnt );
			my @vals = unpack( "v*", $buf );
			print join( ", ", map( sprintf( "0x%04X", $_ ), @vals ) ), "]\n";
			push @quiz_questions, { q1_unk=>sprintf("0x%04X", $q1_unk ), q1_oid=>sprintf("oid_x%04X", $q1_oid), q1_good_reply_oids=>[ map(sprintf("oid_x%04X",$_), @vals )] };
		}
	}

	#stores all questions into quiz
	$ONE_QUIZ{ questions } = \@quiz_questions;

	#stores one quiz into all quizes
	push @{ $BNL{ quiz }{ quizes } }, \%ONE_QUIZ;
}

#this creates 512 bytes long array full of zeroes with some bytes (16 in each block of 64) replaced by pre-key bytes
sub keygen()
{
	my $ar_pre_key = $_[0];

	my @keygen_tbl = (
		[0,1,1,2,0,1,1,2],
		[3,3,2,1,1,2,2,1],
		[2,2,3,1,2,2,3,1],
		[1,0,0,0,1,0,0,0],

		[1,2,0,1,1,2,0,1],
		[1,2,0,2,1,2,2,2],
		[2,1,0,0,2,1,0,0],
		[2,3,2,2,2,3,2,2],

		[3,0,3,1,3,0,3,1],
		[0,0,1,1,0,3,1,1],
		[2,2,3,0,2,2,3,1],
		[3,1,0,0,3,1,0,0],

		[3,3,0,2,3,3,1,2],
		[1,2,0,0,1,2,0,0],
		[2,1,0,3,2,1,3,3],
		[0,0,0,0,0,0,0,0]
	);

	my @key = ( 0 ) x 512;

	for( my $pk_ptr = 0; $pk_ptr < scalar( @$ar_pre_key ); $pk_ptr++ )
	{
		for( my $block = 0; $block < 8; $block++ )
		{
			$key[ $block * 16 * 4 + $pk_ptr * 4 + $keygen_tbl[$pk_ptr][$block] ] = $$ar_pre_key[ $pk_ptr ];
		}
	}
	return @key;
}

sub decrypt_mem()
{
	my $rbuf = $_[0];
	my $ar_key = $_[1];
	my $key_length = scalar( @$ar_key );

	my @d = unpack( "C*", $$rbuf );

	my $kptr = 0;
	foreach my $d ( @d )
	{
		if( $$ar_key[$kptr] )
		{
			if( $d !=0 && $d != 0xFF && $d != $$ar_key[$kptr] && $d != ($$ar_key[$kptr] ^ 0xFF ))
			{
				$d ^= $$ar_key[$kptr];
			}
		}
		$kptr++;
		$kptr = 0 if( $kptr >= $key_length );
	}
	$$rbuf = pack( "C*", @d );
}

#this overwrites $len bytes back from current pointer in $rbuf buffer with # characters
#this is only debugging helper which helps me see which bytes were touched by the disassembler
sub mark_rbuf()
{
	my $len = $_[0];
	my $ptr = sysseek( IN, 0, 1 );

	$hi_rbuf = $ptr if( $ptr > $hi_rbuf );

	$ptr -= $len;
	$lo_rbuf = $ptr if( $ptr < $lo_rbuf );

	die if( $lo_rbuf < 0 );

	substr( $rbuf, $ptr, $len ) = '#' x $len;
}

#this just replaces chars # \0 and \xFF with nothing and counts them
#ideally, when everything is parsed, result is 0
sub verify_rbuf()
{
	my $str = substr( $rbuf, $lo_rbuf, $hi_rbuf-$lo_rbuf );
	$str =~ s/[#\x00\xFF]+//g;

	printf( "coverage: [%08X-%08X] %d\n", $lo_rbuf, $hi_rbuf, length( $str ) );
}

sub oid2rawoid()
{

	my $inp_code = $_[0];
	my $ret = $oid_tbl_int2raw[ $inp_code ];
	$ret = "no such code" unless $ret;
	return $ret;
}

sub rawoid2oid()
{
	my $raw = $_[0];
	for( my $i = 0; $i < scalar( @oid_tbl_int2raw ); $i++ )
	{
		if( $oid_tbl_int2raw[$i] == $raw )
		{
			return $i;
		}
	}
	die;
}

#this function generated by oid_table_extract.pl
sub oid_converter_init()
{
	#index to the array is INTERNAL pen code (index to OID table). Value in the array is RAW, printed code
	@oid_tbl_int2raw = (
		4..7, 12, 15, 20..23, 28, 36..39, 60, 68, 69, 84, 85, 100, 101, 196..199, 204, 207, 212..215,
		223, 228..231, 236, 252, 256, 257, 259, 272, 273, 275, 320, 321, 323, 336, 337, 339, 384..387,
		400..403, 449..451, 465..467, 768, 769, 771, 776..779, 784, 792..795, 801, 808, 809, 816, 817,
		962, 963, 969..971, 979, 985..987, 994, 1001, 1010, 1011, 1280, 1297, 1299, 1305, 1329, 1331,
		1345, 1347, 1360, 1368, 1370, 1392, 1408, 1410, 1425, 1427, 1433, 1435, 1457, 1459, 1473, 1475,
		1490, 1498, 1522, 1542, 1548, 1549, 1551, 1565, 1567, 1596, 1597, 1604..1607, 1612, 1613, 1615,
		1620, 1622, 1628, 1660, 1661, 1670, 1676..1679, 1693, 1695, 1724, 1725, 1734, 1740..1743, 1750,
		1756, 1758, 1788, 1789, 1800, 1802, 1817, 1819, 1841, 1993, 1995, 2010, 2034, 2100, 2102, 2108,
		2165, 2293, 2295, 2304, 2305, 2307, 2320, 2330, 2337, 2339, 2345, 2352, 2353, 2355, 2368, 2369,
		2371, 2385, 2387, 2393, 2395, 2400, 2408, 2416, 2417, 2419, 2434, 2435, 2450, 2456, 2458, 2465,
		2467, 2473, 2480..2483, 2498, 2499, 2515, 2521, 2530, 2545..2547, 2572, 2573, 2575, 2605, 2614,
		2620, 2621, 2636, 2637, 2639, 2660, 2662, 2668, 2676..2679, 2684, 2685, 2702, 2703, 2733, 2742,
		2748, 2749, 2766, 2767, 2790, 2796, 2806, 2812, 2813, 2825, 2827, 2840, 2842, 2857, 2864, 2872,
		3018, 3035, 3059, 3065, 3076..3079, 3084, 3087, 3092..3095, 3103, 3108..3111, 3116, 3124..3127,
		3132, 3140, 3141, 3156, 3157, 3172, 3173, 3188, 3189, 3270, 3271, 3276, 3279, 3286, 3287, 3292,
		3300..3303, 3316..3319, 3324, 3328, 3329, 3331, 3344, 3345, 3347, 3360, 3361, 3363, 3376, 3377,
		3379, 3392, 3393, 3395, 3408, 3409, 3411, 3424, 3425, 3427, 3440, 3441, 3443, 3458, 3459, 3474,
		3475, 3488..3491, 3504..3507, 3522, 3523, 3538, 3539, 3553..3555, 3569..3571, 3848..3851, 3864..3867,
		3880, 3881, 3888, 3889, 3891, 3896, 3897, 4042, 4043, 4058, 4059, 4073, 4082, 4083, 4089, 4096,
		4097, 4099, 4112, 4120..4123, 4129, 4131, 4136, 4137, 4144, 4145, 4147, 4357, 4358, 4373, 4374,
		4423, 4439, 5382, 5388, 5397, 5407, 5447, 5455, 6168, 6170, 6185, 6192, 6405, 6406, 6412, 6415,
		6422, 6428, 6437, 6453, 6454, 6460, 6471, 6479, 6487, 6495, 6519, 7168, 7169, 7171, 7192..7195,
		7200, 7208, 7209, 7216, 7217, 7219, 7429, 7430, 7445, 7446, 7461, 7462, 7477, 7478, 7495, 7511,
		7527, 7543, 8192, 8193, 8195, 8209, 8211, 8216..8219, 8224, 8232, 8233, 8240, 8241, 8243, 8323,
		8327, 8339, 8343, 8359, 8371, 8384..8391, 8396, 8399, 8400, 8402, 8404..8411, 8415, 8417, 8419..8425,
		8428, 8432..8435, 8444, 8453, 8454, 8469, 8470, 8519, 8535, 8579, 8583, 8595, 8599, 8643, 8645,
		8646, 8659, 8661, 8662, 9217, 9219, 9240, 9242, 9264, 9347, 9408, 9410, 9433, 9435, 9457, 9459,
		9477, 9478, 9484, 9487, 9494, 9500, 9532, 9543, 9551, 9559, 9567, 9607, 9615, 9619, 9627, 9651,
		9667, 9669, 9670, 9676, 9679, 9685, 9690, 9695, 9724, 10240, 10265, 10267, 10280, 10289, 10291,
		10292, 10294, 10300, 10419, 10435, 10456, 10458, 10473, 10480, 10482, 10485, 10487, 10496,
		10499, 10502, 10508, 10512, 10517, 10522, 10527, 10531, 10534, 10537, 10540, 10544, 10547,
		10549, 10563, 10567, 10575, 10579, 10587, 10599, 10611, 10627, 10647, 10655, 10659, 10675,
		10679, 10691, 10703, 10707, 10710, 10713, 10716, 10725, 10739, 10742, 10748, 11264, 11265,
		11267..11271, 11276, 11279, 11284..11291, 11295, 11297, 11299..11305, 11308, 11312, 11313,
		11315..11319, 11324, 11395, 11399, 11415, 11427, 11431, 11443, 11447, 11458, 11459, 11462,
		11463, 11468, 11471, 11478..11484, 11488, 11490, 11492..11497, 11504..11511, 11516, 11520,
		11523, 11536, 11539, 11552, 11555, 11568, 11571, 11587, 11603, 11619, 11635, 11651, 11667,
		11683, 11699, 11715, 11731, 11747, 11763, 12292..12295, 12300, 12303, 12308..12311, 12319,
		12324..12327, 12332, 12348, 12419, 12423, 12439, 12451, 12455, 12467, 12480..12487, 12492,
		12495, 12497, 12499..12508, 12512, 12514, 12516..12521, 12528..12531, 12540, 12544, 12545,
		12547, 12560, 12561, 12563, 12611, 12627, 12675, 12679, 12691, 12695, 12737..12739, 12741,
		12742, 12753..12755, 12757, 12758, 13056, 13057, 13059, 13061..13069, 13071, 13073, 13075,
		13077..13084, 13088, 13093, 13096, 13097, 13101, 13104, 13105, 13116, 13117, 13250, 13251,
		13254, 13255, 13257..13263, 13266, 13270, 13271, 13273..13275, 13277, 13279, 13283, 13286,
		13287, 13289, 13292, 13298, 13299, 13308, 13309, 13317, 13319, 13327, 13332, 13334, 13372,
		13447, 13508, 13510, 13516, 13525, 13527, 13568, 13569, 13571, 13584, 13594, 13616, 13617,
		13619, 13635, 13651, 13659, 13683, 13699, 13719, 13727, 13747, 13761..13763, 13765, 13775,
		13777, 13779, 13782, 13785, 13788, 13809..13811, 13820, 13830, 13833, 13834, 13836, 13837,
		13839, 13846, 13849, 13852, 13872, 13873, 13884, 13885, 13891, 13895, 13899, 13903, 13911,
		13919, 13963, 13967, 13979, 14003, 14018, 14022, 14026, 14028..14031, 14042, 14045, 14047,
		14066, 14076, 14077, 14089, 14091, 14104, 14106, 14128, 14141, 14282, 14297, 14299, 14323,
		14332, 14340, 14342, 14348, 14360, 14362, 14372, 14374, 14377, 14384, 14389, 14391, 14519,
		14535, 14543, 14553, 14555, 14565, 14567, 14568, 14577, 14579, 14580, 14582, 14588, 14592,
		14597, 14598, 14604, 14607, 14609, 14611, 14614, 14617, 14620, 14624, 14629, 14641, 14643,
		14645, 14646, 14652, 14659, 14663, 14671, 14679, 14687, 14691, 14711, 14727, 14735, 14739,
		14747, 14759, 14771, 14775, 14787, 14790, 14796, 14799, 14802, 14810, 14815, 14817, 14819,
		14822, 14825, 14828, 14834, 14837, 14838, 14844, 14857, 14858, 14860, 14874, 14886, 14889,
		14892, 14896, 14897, 14899, 14905, 14909, 14923, 14927, 14939, 14951, 14963, 14987, 15027,
		15050, 15055, 15074, 15085, 15090, 15094, 15100, 15112, 15114, 15129, 15131, 15144, 15153,
		15155, 15158, 15161, 15164, 15307, 15322, 15337, 15346, 15351, 15357, 15360, 15361, 15363..15367,
		15372, 15375, 15380..15388, 15392, 15396..15401, 15408, 15409, 15411..15415, 15420, 15491,
		15495, 15511, 15527, 15539, 15543, 15554, 15555, 15558, 15559, 15564, 15567, 15574..15579,
		15583, 15585, 15587..15593, 15596, 15600..15607, 15612, 15621, 15622, 15637, 15638, 15653,
		15654, 15669, 15670, 15687, 15703, 15719, 15735, 15751, 15767, 15783, 15799, 15814, 15830,
		15845, 15846, 15861, 15862, 16136..16141, 16143, 16152..16155, 16157, 16159, 16166, 16168,
		16169, 16172, 16176, 16177, 16179, 16181..16185, 16188, 16189, 16330, 16331, 16334, 16335,
		16346, 16347, 16350, 16358, 16361, 16365, 16370, 16371, 16374, 16375, 16377, 16380, 16381,
		16384, 16385, 16387, 16400, 16401, 16403, 16409, 16410, 16416, 16417, 16419, 16425, 16432,
		16433, 16435, 16448, 16449, 16464, 16465, 16480, 16481, 16496, 16497, 16576..16579, 16592..16595,
		16601, 16602, 16608..16611, 16617, 16624..16627, 16709, 16725, 16726, 16774, 16789, 16790,
		17158, 17164, 17173, 17181, 17183, 17196, 17213, 17357, 17359, 17366, 17372, 17374, 17389,
		17404, 17408, 17409, 17411, 17433, 17456, 17457, 17459, 17472, 17473, 17520, 17521, 17600..17603,
		17626, 17648..17651, 17733, 17734, 17740, 17743, 17750, 17756, 17788, 17797, 17798, 17804,
		17807, 17813, 17823, 17852, 17984, 17994, 18033, 18057, 18098, 18189, 18191, 18236, 18374,
		18380, 18382, 18429, 18432, 18433, 18435, 18458, 18473, 18480, 18481, 18483, 18496, 18497,
		18544, 18545, 18626, 18627, 18649, 18672..18675, 18757, 18758, 18764, 18767, 18773, 18783,
		18790, 18796, 18805, 18806, 18812, 18822, 18828, 18831, 18838, 18844, 18853, 18869, 18870,
		18876, 19017, 19056, 19082, 19123, 19129, 19253, 19261, 19446, 19452, 19456, 19457, 19459,
		19481, 19482, 19488, 19489, 19491, 19497, 19504, 19505, 19507, 19520, 19521, 19552, 19553,
		19568, 19569, 19650, 19651, 19673, 19674, 19680..19683, 19689, 19696..19699, 19782, 19797,
		19798, 19813, 19814, 19829, 19862, 19877, 19878, 19894, 20237, 20239, 20252, 20269, 20278,
		20284, 20430, 20447, 20454, 20460, 20477, 20484..20487, 20492, 20495, 20500..20503, 20508,
		20511, 20516..20519, 20524, 20540, 20676..20679, 20684, 20687, 20692..20695, 20700, 20703,
		20708..20711, 20716, 20732, 20736, 20737, 20739, 20752, 20753, 20755, 20803, 20819, 20867,
		20883, 20929..20931, 20945..20947, 21248, 21256, 21258, 21265, 21267, 21273, 21275, 21280,
		21288, 21297, 21443, 21449, 21451, 21458, 21466, 21475, 21481, 21490, 21509, 21511, 21516,
		21519, 21525, 21527, 21564, 21700, 21702, 21708, 21711, 21716, 21718, 21756, 21760, 21761,
		21763, 21777, 21779, 21785, 21808, 21809, 21811, 21827, 21875, 21891, 21907, 21915, 21939,
		21953..21955, 21970, 21978, 22001..22003, 22029, 22031, 22076, 22159, 22214, 22220, 22222,
		22269, 22281, 22283, 22320, 22474, 22515, 22532, 22534, 22540, 22543, 22565, 22567, 22581,
		22583, 22588, 22727, 22732, 22735, 22756, 22758, 22772, 22774, 22780, 22784, 22785, 22787,
		22800, 22810, 22817, 22819, 22825, 22832, 22833, 22835, 22851, 22867, 22875, 22899, 22915,
		22947, 22963, 22978, 22979, 22995, 23001, 23010, 23025..23027, 23052, 23101, 23119, 23247,
		23286, 23292, 23304, 23306, 23345, 23347, 23353, 23499, 23538, 23556..23559, 23564, 23567,
		23572..23575, 23580, 23583, 23588..23591, 23596, 23604..23607, 23612, 23750, 23751, 23756,
		23759, 23766, 23767, 23772, 23775, 23780..23783, 23788, 23796..23799, 23804, 23808, 23809,
		23811, 23824, 23825, 23827, 23840, 23841, 23843, 23856, 23857, 23859, 23875, 23891, 23907,
		23923, 23939, 23955, 23971, 23987, 24002, 24003, 24018, 24019, 24033..24035, 24049..24051,
		24329, 24331, 24344, 24346, 24361, 24368, 24376, 24522, 24539, 24563, 24569, 24580..24583,
		24588, 24591, 24596..24599, 24604, 24607, 24612..24615, 24620, 24636, 24707, 24711, 24723,
		24727, 24739, 24743, 24755, 24768..24775, 24780, 24783..24796, 24799..24809, 24812, 24816..24819,
		24828, 24899, 24915, 24963, 24979, 24983, 25026, 25042, 25046, 25345, 25347, 25350, 25353,
		25355, 25356, 25360, 25365, 25367, 25368, 25370, 25373, 25375, 25377, 25385, 25388, 25392,
		25405, 25538, 25543, 25546, 25549, 25551, 25555, 25558, 25561, 25563, 25564, 25566, 25570,
		25575, 25581, 25587, 25596, 25604, 25606, 25612, 25615, 25620, 25622, 25660, 25731, 25779,
		25792..25795, 25797, 25799, 25804, 25807, 25813, 25815, 25816, 25818, 25840..25843, 25852,
		25923, 25939, 25947, 25971, 25987, 25991, 25999, 26007, 26015, 26035, 26050, 26054, 26060,
		26063, 26070, 26076, 26098, 26108, 26118, 26124, 26173, 26183, 26191, 26251, 26306, 26314,
		26317, 26319, 26364, 26376, 26378, 26381, 26383, 26417, 26428, 26566, 26569, 26571, 26572,
		26574, 26610, 26621, 26624, 26625, 26627, 26648, 26650, 26665, 26672, 26673, 26675, 26755,
		26803, 26818, 26819, 26841, 26843, 26856, 26864..26867, 26951, 26959, 26967, 26975, 26999,
		27015, 27023, 27047, 27063, 27078, 27084, 27087, 27103, 27110, 27116, 27126, 27132, 27146,
		27211, 27315, 27378, 27445, 27447, 27453, 27638, 27644, 27648, 27649, 27651, 27652, 27654,
		27660, 27669, 27671..27675, 27679..27681, 27683, 27684, 27686, 27688, 27689, 27692, 27696,
		27697, 27699, 27701, 27703, 27779, 27799, 27811, 27827, 27831, 27842, 27843, 27847, 27855,
		27862, 27864..27868, 27872..27875, 27877, 27879..27881, 27888..27892, 27894, 27900, 27991,
		28007, 28023, 28039, 28055, 28071, 28102, 28118, 28134, 28424, 28426, 28429, 28431, 28441,
		28443, 28444, 28456, 28461, 28465, 28467, 28470, 28473, 28476, 28619, 28622, 28634, 28639,
		28646, 28649, 28652, 28658, 28663, 28669, 28803, 28807, 28819, 28823, 28835, 28839, 28851,
		28864..28867, 28869, 28870, 28876, 28879..28883, 28885, 28886, 28889, 28890, 28892, 28895..28899,
		28901, 28902, 28905, 28908, 28912..28915, 28924, 29059, 29075, 29440, 29445, 29450, 29453,
		29455, 29457, 29459, 29462, 29465, 29468, 29472, 29477, 29485, 29489, 29500, 29635, 29638,
		29641, 29644, 29646, 29650, 29658, 29661, 29663, 29667, 29670, 29673, 29676, 29682, 29693,
		29827, 29831, 29847, 29875, 29888..29891, 29894, 29900, 29903, 29910, 29913, 29936..29939,
		29948, 30031, 30047, 30083, 30095, 30099, 30131, 30275, 30351, 30387, 30470, 30473, 30476,
		30512, 30525, 30666, 30669, 30671, 30707, 30716, 30887, 30903, 30924, 30927, 30950, 30966,
		30972, 31043, 31059, 31091, 31107, 31139, 31155, 31311, 31498, 31537, 31539, 31545, 31730,
		31879, 31895, 31911, 31923, 31927, 31939, 31942, 31948, 31951, 31958, 31962, 31964, 31967,
		31969, 31971, 31973, 31974, 31977, 31980, 31984, 31986, 31989, 31990, 31996, 32067, 32083,
		32099, 32115, 32131, 32147, 32163, 32179, 32521, 32524, 32538, 32541, 32543, 32550, 32553,
		32556, 32560, 32565, 32573, 32714, 32719, 32734, 32749, 32755, 32758, 32761, 32764, 32768,
		32785, 32787, 32793, 32800, 32817, 32819, 32833, 32848, 32865, 32880, 32961, 32963, 32976,
		32978, 32986, 32993, 32995, 33001, 33008, 33010, 33157, 33173, 33174, 33344, 33345, 33347,
		33349, 33354, 33356, 33357, 33359..33361, 33363, 33365, 33366, 33369, 33370, 33372, 33373,
		33375, 33410, 33411, 33414, 33417, 33420..33423, 33426, 33427, 33430, 33433, 33434, 33436..33439,
		33536, 33537, 33539, 33541, 33542, 33545, 33546, 33548, 33549, 33551..33553, 33555, 33557,
		33558, 33561, 33562, 33564, 33565, 33567..33569, 33573, 33577, 33580, 33581, 33584, 33585,
		33596, 33597, 33600, 33601, 33604, 33605, 33608, 33609, 33612, 33613, 33616, 33617, 33620,
		33621, 33624, 33625, 33628, 33629, 33632, 33633, 33636, 33637, 33640, 33641, 33644, 33645,
		33648, 33649, 33660, 33661, 33730, 33731, 33734, 33737, 33738, 33740..33743, 33746, 33747,
		33750, 33753, 33754, 33756..33759, 33762, 33763, 33766, 33769, 33772, 33773, 33778, 33779,
		33788, 33789, 33793, 33795, 33818, 33840, 33856, 33905, 33984, 33986, 34009, 34033, 34035,
		34181, 34182, 34188, 34191, 34198, 34204, 34236, 34368, 34369, 34371, 34373, 34374, 34377,
		34378, 34380, 34381, 34383, 34390, 34393, 34396, 34416, 34417, 34428, 34429, 34434, 34438,
		34441, 34442, 34444..34447, 34458, 34461, 34463, 34482, 34483, 34492, 34493, 34573, 34575,
		34582, 34585, 34609, 34620, 34621, 34636, 34645, 34648, 34672, 34684, 34685, 34764, 34766,
		34778, 34802, 34812, 34813, 35202, 35203, 35218, 35226, 35233, 35235, 35241, 35248..35251,
		35404, 35405, 35407, 35430, 35436, 35445, 35446, 35452, 35453, 35470, 35471, 35501, 35510,
		35516, 35517, 35594, 35610, 35625, 35632, 35633, 35635, 35641, 35657, 35673, 35688, 35696,
		35697, 35704, 35826, 35827, 35840, 35845, 35846, 35852, 35855, 35861, 35862, 35865, 35868,
		35871, 35872, 35877, 35878, 35884, 35889, 35891, 35893, 35894, 35900, 35905, 35908, 35909,
		35924, 35925, 35937, 35940, 35941, 35952, 35956, 35957, 36038, 36044, 36047, 36054, 36060,
		36063, 36069, 36070, 36076, 36085, 36086, 36092, 36226, 36227, 36242, 36243, 36256..36259,
		36272..36275, 36428, 36429, 36431, 36444, 36445, 36447, 36453, 36454, 36460, 36461, 36469,
		36476, 36477, 36494, 36495, 36510, 36511, 36518, 36524, 36525, 36534, 36540, 36541, 36617,
		36618, 36620, 36633, 36634, 36637, 36639, 36646, 36649, 36652, 36656, 36657, 36659, 36661,
		36665, 36669, 36680, 36681, 36685, 36696, 36697, 36700, 36709, 36712, 36713, 36717, 36720,
		36721, 36724, 36728, 36729, 36732, 36810, 36815, 36826, 36830, 36841, 36845, 36850, 36851,
		36854, 36857, 36860, 36868..36871, 36876, 36879, 36884..36887, 36892, 36895, 36900..36903,
		36908, 36924, 37060..37063, 37068, 37071, 37076..37079, 37084, 37087, 37092..37095, 37100,
		37116, 37120, 37121, 37123, 37136, 37137, 37139, 37187, 37203, 37251, 37267, 37313..37315,
		37329..37331, 37376, 37377, 37379, 37386, 37388, 37389, 37391..37393, 37395, 37398, 37401,
		37402, 37404, 37405, 37407, 37443, 37451, 37455, 37459, 37463, 37467, 37471, 37507, 37519,
		37523, 37531, 37535, 37570, 37574, 37580..37583, 37586, 37590, 37594, 37596..37599, 37632,
		37633, 37635, 37637..37645, 37647..37649, 37651, 37653..37661, 37663..37665, 37669, 37672,
		37673, 37676, 37677, 37680, 37681, 37692, 37693, 37826, 37827, 37830, 37831, 37833..37839,
		37842, 37843, 37846, 37847, 37849..37855, 37858, 37859, 37862, 37863, 37865, 37868, 37869,
		37874, 37875, 37884, 37885, 37903, 37908, 37910, 37948, 38092, 38101, 38103, 38144, 38145,
		38147, 38160, 38170, 38192, 38193, 38195, 38211, 38227, 38235, 38259, 38275, 38323, 38337..38339,
		38353, 38355, 38361, 38385..38387, 38406, 38409, 38410, 38412, 38413, 38415, 38422, 38425,
		38428, 38448, 38449, 38460, 38461, 38467, 38471, 38475, 38479, 38487, 38495, 38539, 38543,
		38555, 38579, 38594, 38598, 38602, 38604..38607, 38618, 38621, 38623, 38642, 38652, 38653,
		38664, 38666, 38680, 38682, 38704, 38705, 38717, 38857, 38859, 38873, 38875, 38898, 38899,
		38908, 38936, 38938, 38953, 38960, 38961, 38963, 39129, 39131, 39144, 39152..39155, 39173,
		39174, 39180, 39183, 39190, 39196, 39205, 39221, 39222, 39228, 39239, 39247, 39255, 39263,
		39287, 39303, 39311, 39335, 39351, 39366, 39372, 39375, 39391, 39398, 39404, 39413, 39414,
		39420, 39433, 39434, 39450, 39465, 39472, 39473, 39475, 39481, 39499, 39515, 39539, 39563,
		39603, 39626, 39650, 39666, 39733, 39735, 39740, 39741, 39926, 39932, 39933, 39936, 39937,
		39939, 39940, 39942, 39948, 39957, 39959..39963, 39967..39969, 39971, 39972, 39974, 39976,
		39977, 39980, 39984, 39985, 39987, 39989, 39991, 40130, 40131, 40152..40155, 40160..40163,
		40168, 40169, 40176..40179, 40197, 40213, 40214, 40229, 40230, 40246, 40279, 40295, 40311,
		40327, 40343, 40359, 40390, 40406, 40421, 40422, 40437, 40457, 40473, 40474, 40489, 40496,
		40497, 40499, 40539, 40547, 40563, 40587, 40603, 40627, 40650, 40666, 40674, 40690, 40712,
		40714, 40716, 40717, 40719, 40729, 40731..40733, 40735, 40742, 40744, 40748, 40749, 40753,
		40755, 40757..40759, 40761, 40764, 40765, 40907, 40910, 40911, 40922, 40926, 40927, 40934,
		40937, 40940, 40941, 40946, 40950, 40951, 40956, 40957, 41091, 41107, 41123, 41139, 41153,
		41155, 41168, 41170, 41176, 41178, 41185, 41187, 41193, 41200, 41202, 41351, 41367, 41498,
		41539, 41555, 41563, 41603, 41611, 41615, 41619, 41627, 41631, 41666, 41674, 41676..41679,
		41682, 41686, 41690, 41692..41695, 41733..41735, 41740, 41741, 41743, 41749..41751, 41756,
		41757, 41759, 41765, 41772, 41773, 41788, 41789, 41859, 41863, 41867, 41871, 41875, 41879,
		41883, 41887, 41891, 41895, 41907, 41922, 41923, 41926, 41927, 41929..41935, 41938, 41939,
		41942, 41943, 41945..41951, 41954, 41955, 41958, 41959, 41961, 41964, 41965, 41970, 41971,
		41980, 41981, 42115, 42176, 42178, 42201, 42203, 42225, 42227, 42375, 42383, 42506, 42522,
		42563, 42571, 42587, 42635, 42639, 42655, 42675, 42690, 42694, 42698, 42700..42703, 42710,
		42716, 42718, 42738, 42748, 42749, 42765, 42767, 42774, 42812, 42813, 42895, 42907, 42931,
		42956, 42958, 42970, 42994, 43004, 43005, 43191, 43395, 43427, 43443, 43532, 43533, 43535,
		43565, 43574, 43580, 43581, 43599, 43639, 43663, 43726, 43727, 43750, 43756, 43766, 43772,
		43773, 43784, 43786, 43800, 43802, 43817, 43824, 43825, 43827, 43833, 43955, 43979, 43995,
		44018, 44019, 44167, 44183, 44199, 44211, 44215, 44227, 44230, 44231, 44236, 44239, 44246..44248,
		44250, 44252, 44255, 44257, 44259..44263, 44265, 44268, 44272, 44274, 44276..44279, 44284,
		44419, 44435, 44451, 44467, 44556, 44557, 44559, 44572, 44573, 44575, 44582, 44588, 44589,
		44598, 44604, 44605, 44623, 44639, 44647, 44663, 44687, 44703, 44750, 44751, 44766, 44767,
		44774, 44780, 44781, 44796, 44797, 44808..44812, 44824..44827, 44829, 44831, 44838, 44840,
		44841, 44844, 44848, 44849, 44851, 44853, 44855..44857, 44861, 44939, 44955, 44959, 44979,
		44983, 45002, 45003, 45007, 45018, 45019, 45022, 45033, 45037, 45042, 45043, 45046, 45049,
		45052, 45191, 45207, 45223, 45443, 45459, 45699, 45711, 45715, 45727, 45824, 45825, 45827,
		45833, 45834, 45840, 45841, 45843, 45849, 45850, 45856, 45857, 45865, 45872, 45873, 45955,
		45959, 45963, 45967, 45971, 45975, 45979, 45983, 45987, 45991, 46003, 46018, 46019, 46022,
		46025, 46026, 46028..46031, 46034, 46035, 46038, 46041, 46042, 46044..46047, 46050, 46051,
		46054, 46057, 46060, 46061, 46066, 46067, 46076, 46077, 46467, 46515, 46735, 46771, 46858,
		46874, 46896, 46897, 47027, 47049, 47065, 47090, 47091, 47100, 47283, 47503, 47795, 47925,
		47932, 47933, 48055, 48118, 48124, 48125, 48259, 48279, 48291, 48307, 48311, 48819, 48906,
		48908, 48909, 48911, 48921, 48924, 48925, 48927, 48934, 48940, 48941, 48945, 48947, 48949,
		48950, 48953, 48956, 48957, 49039, 49051, 49055, 49075, 49079, 49102, 49103, 49114, 49118,
		49119, 49126, 49129, 49132, 49133, 49138, 49142, 49148, 49149, 49156, 49158, 49164, 49173,
		49175, 49183, 49188, 49190, 49196, 49221, 49236, 49253, 49349, 49351, 49359, 49364, 49366,
		49372, 49381, 49383, 49404, 49473, 49475, 49488, 49536..49539, 49552..49555, 49618, 49670,
		49674, 49676, 49677, 49679, 49686, 49690, 49692, 49693, 49695, 49728, 49729, 49731..49741,
		49743..49745, 49747..49757, 49759, 49794, 49795, 49798, 49800..49807, 49810, 49811, 49814,
		49816..49823, 49858, 49862, 49866, 49868..49871, 49874, 49878, 49882, 49884..49887, 49920,
		49921, 49923, 49925, 49927..49931, 49933, 49935, 49937, 49939, 49942, 49944..49948, 49952,
		49957, 49960, 49961, 49965, 49968, 49969, 49980, 49984, 49985, 49988, 49992, 49993, 49996,
		50000, 50005, 50008, 50009, 50013, 50017, 50020, 50024, 50025, 50028, 50032, 50033, 50045,
		50114, 50115, 50118, 50121..50124, 50126, 50130, 50135, 50137..50139, 50141, 50143, 50147,
		50150, 50153, 50156, 50162, 50163, 50173, 50181, 50183, 50191, 50196, 50198, 50236, 50244,
		50261, 50372, 50374, 50380, 50389, 50391, 50496, 50513, 50515, 50521, 50523, 50545, 50547,
		50560..50563, 50576, 50578, 50584, 50586, 50608..50611, 50626, 50694, 50698, 50700, 50701,
		50703, 50710, 50716, 50748, 50749, 50752, 50753, 50755..50765, 50767, 50773, 50775, 50776,
		50778, 50781, 50783, 50800, 50801, 50812, 50813, 50818, 50822, 50824..50831, 50838, 50841,
		50843, 50844, 50846, 50866, 50867, 50876, 50877, 50882, 50886, 50890, 50892..50895, 50906,
		50909, 50911, 50930, 50940, 50941, 50953, 50955, 50968, 50970, 50992, 51005, 51016, 51033,
		51057, 51068, 51146, 51161, 51163, 51187, 51196, 51204, 51206, 51212, 51236, 51238, 51253,
		51255, 51269, 51301, 51316, 51521, 51523, 51536, 51544, 51546, 51553, 51555, 51561, 51568,
		51591, 51599, 51606, 51612, 51621, 51623, 51638, 51644, 51722, 51724, 51738, 51750, 51756,
		51773, 51784..51787, 51789, 51791, 51801, 51803, 51808, 51813, 51815, 51816, 51821, 51824,
		51825, 51827, 51828, 51830, 51832, 51833, 51836, 51850, 51851, 51854, 51866, 51878, 51881,
		51884, 51890, 51891, 51896, 51897, 51901, 51914, 51919, 51938, 51949, 51954, 51958, 51964,
		51976, 51978, 51993, 51995, 52008, 52017, 52019, 52022, 52025, 52028, 52041, 52056, 52073,
		52080, 52085, 52088, 52093, 52171, 52186, 52201, 52210, 52215, 52221, 52224, 52225, 52227..52231,
		52236, 52239, 52244..52252, 52256, 52260..52265, 52272, 52273, 52275..52279, 52284, 52288,
		52289, 52292, 52293, 52308, 52309, 52321, 52324, 52325, 52336, 52337, 52340, 52341, 52418,
		52419, 52440..52443, 52449, 52451, 52456, 52457, 52464..52467, 52548..52551, 52564..52567,
		52580..52583, 52596..52599, 52614, 52615, 52630, 52631, 52645..52647, 52661..52663, 52678,
		52694, 52710, 52726, 52746, 52762, 52808..52811, 52824..52827, 52832, 52833, 52835, 52840,
		52841, 52848, 52849, 52851, 52856, 52857, 52874, 52875, 52890, 52891, 52898, 52904, 52905,
		52914, 52915, 52920, 52921, 52938, 52954, 52962, 52978, 53000..53005, 53007, 53016..53019,
		53021, 53023, 53030, 53032, 53033, 53036, 53040, 53041, 53043, 53045..53049, 53052, 53053,
		53064, 53065, 53068, 53069, 53080, 53081, 53084, 53092, 53093, 53096, 53097, 53101, 53104,
		53105, 53108, 53109, 53112, 53113, 53116, 53117, 53194, 53195, 53198, 53199, 53210, 53211,
		53214, 53222, 53225, 53229, 53234, 53235, 53238, 53239, 53241, 53244, 53245, 53248, 53265,
		53267, 53273, 53275, 53280, 53288, 53297, 53299, 53509, 53510, 53525, 53526, 53575, 53591,
		53760, 53763, 53766, 53769, 53770, 53772, 53775, 53776, 53779, 53782, 53785, 53786, 53788,
		53791, 53827, 53831, 53835, 53839, 53843, 53847, 53851, 53855, 54017, 54019, 54021..54023,
		54025, 54027..54029, 54031, 54032, 54037..54040, 54042, 54045, 54047, 54049, 54053, 54057,
		54060, 54064, 54076, 54077, 54273, 54275, 54296, 54298, 54320, 54533, 54534, 54540, 54543,
		54550, 54556, 54588, 54599, 54607, 54615, 54623, 54790, 54793, 54794, 54796, 54799, 54810,
		54815, 54832, 54844, 54851, 54855, 54859, 54863, 54875, 55048, 55050, 55053, 55055, 55062,
		55065, 55067, 55089, 55100, 55296, 55321, 55323, 55336, 55345, 55347, 55555, 55558, 55564,
		55568, 55573, 55578, 55583, 55587, 55590, 55593, 55596, 55600, 55605, 55623, 55631, 55635,
		55643, 55655, 55667, 55818, 55820, 55823, 55833, 55859, 55862, 55865, 55868, 55883, 55887,
		55907, 55927, 56073, 56075, 56088, 56090, 56105, 56112, 56117, 56119, 56120, 56125, 56320,
		56321, 56323..56327, 56332, 56335, 56340..56347, 56351, 56353, 56355..56361, 56364, 56368,
		56369, 56371..56375, 56380, 56576, 56579, 56592, 56595, 56608, 56611, 56624, 56627, 56643,
		56659, 56675, 56691, 56844, 56847, 56860, 56863, 56870, 56876, 56886, 56892, 56911, 56927,
		56935, 56951, 57096..57101, 57103, 57112..57116, 57126, 57128, 57129, 57133, 57136, 57137,
		57139, 57141..57145, 57148, 57149, 57495, 57541, 57543, 57551, 57556, 57558, 57564, 57573,
		57575, 57596, 57731, 57747, 57862, 57868, 57871, 57878, 57884, 57887, 57927, 57935, 57943,
		57951, 57987, 57995, 57999, 58003, 58011, 58015, 58054, 58058, 58060, 58063, 58070, 58074,
		58076, 58079, 58112, 58113, 58115, 58120..58123, 58129, 58131, 58136..58139, 58144, 58152,
		58153, 58160, 58161, 58243, 58247, 58251, 58255, 58259, 58267, 58279, 58291, 58306, 58307,
		58310, 58313..58316, 58318, 58322, 58327, 58329..58331, 58333, 58335, 58339, 58342, 58345,
		58348, 58354, 58355, 58365, 58503, 58564, 58566, 58572, 58581, 58583, 58755, 58803, 58886,
		58892, 58895, 58902, 58908, 58940, 58951, 58959, 58967, 58975, 59019, 59023, 59035, 59059,
		59078, 59082, 59084, 59087, 59098, 59103, 59132, 59145, 59147, 59160, 59162, 59184, 59275,
		59338, 59353, 59355, 59379, 59388, 59575, 59591, 59599, 59621, 59623, 59636, 59638, 59644,
		59783, 59791, 59795, 59803, 59815, 59827, 59866, 59914, 59916, 59930, 59942, 59948, 59979,
		59983, 59995, 60007, 60019, 60043, 60083, 60106, 60111, 60150, 60156, 60168, 60170, 60185,
		60187, 60200, 60209, 60211, 60214, 60217, 60220, 60315, 60339, 60363, 60378, 60393, 60402,
		60407, 60413, 60547, 60551, 60567, 60583, 60595, 60599, 60610, 60611, 60614, 60615, 60620,
		60623, 60630..60635, 60639, 60641, 60643..60649, 60652, 60656..60663, 60668, 60807, 60823,
		60839, 60855, 60870, 60886, 60902, 60918, 60938, 60954, 61003, 61019, 61027, 61043, 61067,
		61083, 61107, 61130, 61146, 61192..61197, 61199, 61208..61211, 61213, 61215, 61222, 61224,
		61225, 61228, 61232, 61233, 61235, 61237..61241, 61244, 61245, 61323, 61327, 61339, 61343,
		61363, 61367, 61386, 61387, 61390, 61391, 61402, 61403, 61406, 61414, 61417, 61421, 61426,
		61427, 61430, 61431, 61433, 61436, 61437, 61587, 61619, 61633, 61635, 61648, 61650, 61656,
		61658, 61665, 61667, 61673, 61680, 61682, 61831, 61847, 61910, 62019, 62027, 62035, 62043,
		62083, 62091, 62095, 62099, 62107, 62111, 62146, 62150, 62154, 62156..62159, 62162, 62166,
		62170, 62172..62175, 62213..62215, 62220, 62221, 62223, 62229..62231, 62237, 62239, 62245,
		62252, 62268, 62269, 62339, 62343, 62347, 62351, 62359, 62367, 62371, 62375, 62402, 62406,
		62407, 62410, 62412..62415, 62419, 62422, 62423, 62425, 62427, 62428, 62430, 62434, 62438,
		62439, 62445, 62451, 62460, 62461, 62595, 62656, 62658, 62681, 62683, 62705, 62707, 62855,
		62863, 62918, 62924, 62943, 63043, 63051, 63067, 63115, 63119, 63135, 63155, 63170, 63174,
		63178, 63180..63183, 63190, 63196, 63198, 63218, 63228, 63229, 63245, 63247, 63254, 63292,
		63375, 63387, 63411, 63430, 63433, 63435, 63436, 63438, 63450, 63474, 63485, 63667, 63683,
		63704, 63706, 63721, 63728, 63730, 63875, 63895, 63903, 63907, 63927, 63951, 63958, 63964,
		63990, 63996, 64075, 64079, 64099, 64119, 64143, 64155, 64179, 64206, 64207, 64218, 64230,
		64236, 64242, 64246, 64252, 64253, 64265, 64267, 64280, 64282, 64297, 64304, 64309, 64311,
		64312, 64317, 64395, 64439, 64458, 64475, 64499, 64502, 64505, 64508, 64643, 64647, 64663,
		64675, 64679, 64691, 64695, 64706, 64707, 64710, 64711, 64716, 64719, 64726..64732, 64736,
		64738, 64740..64745, 64752..64759, 64764, 64899, 64915, 64931, 64947, 64962, 64978, 64994,
		65010, 65103, 65119, 65127, 65143, 65167, 65183, 65230, 65231, 65246, 65247, 65254, 65260,
		65261, 65270, 65276, 65277, 65288..65293, 65295, 65304..65308, 65318, 65320, 65321, 65325,
		65328, 65329, 65331, 65333..65337, 65340, 65341, 65419, 65423, 65435, 65459, 65463, 65482,
		65483, 65486, 65487, 65498, 65499, 65503, 65510, 65513, 65516, 65522, 65523, 65526, 65527,
		65529, 65532, 65533, 0..3, 8..11, 13, 14, 16..19, 24..27, 29..35, 40..59, 61..67, 70..83, 86..99,
		102..195, 200..203, 205, 206, 208..211, 216..222, 224..227, 232..235, 237..251, 253..255, 258,
		260..271, 274, 276..319, 322, 324..335, 338, 340..383, 388..399, 404..448, 452..464, 468..767,
		770, 772..775, 780..783, 785..791, 796..800, 802..807, 810..815, 818..961, 964..968, 972..978,
		980..984, 988..993, 995..1000, 1002..1009, 1012..1279, 1281..1296, 1298, 1300..1304, 1306..1328,
		1330, 1332..1344, 1346, 1348..1359, 1361..1367, 1369, 1371..1391, 1393..1407, 1409, 1411..1424,
		1426, 1428..1432, 1434, 1436..1456, 1458, 1460..1472, 1474, 1476..1489, 1491..1497, 1499..1521,
		1523..1541, 1543..1547, 1550, 1552..1564, 1566, 1568..1595, 1598..1603, 1608..1611, 1614, 1616..1619,
		1621, 1623..1627, 1629..1659, 1662..1669, 1671..1675, 1680..1692, 1694, 1696..1723, 1726..1733,
		1735..1739, 1744..1749, 1751..1755, 1757, 1759..1787, 1790..1799, 1801, 1803..1816, 1818, 1820..1840,
		1842..1992, 1994, 1996..2009, 2011..2033, 2035..2099, 2101, 2103..2107, 2109..2164, 2166..2292,
		2294, 2296..2303, 2306, 2308..2319, 2321..2329, 2331..2336, 2338, 2340..2344, 2346..2351, 2354,
		2356..2367, 2370, 2372..2384, 2386, 2388..2392, 2394, 2396..2399, 2401..2407, 2409..2415, 2418,
		2420..2433, 2436..2449, 2451..2455, 2457, 2459..2464, 2466, 2468..2472, 2474..2479, 2484..2497,
		2500..2514, 2516..2520, 2522..2529, 2531..2544, 2548..2571, 2574, 2576..2604, 2606..2613, 2615..2619,
		2622..2635, 2638, 2640..2659, 2661, 2663..2667, 2669..2675, 2680..2683, 2686..2701, 2704..2732,
		2734..2741, 2743..2747, 2750..2765, 2768..2789, 2791..2795, 2797..2805, 2807..2811, 2814..2824,
		2826, 2828..2839, 2841, 2843..2856, 2858..2863, 2865..2871, 2873..3017, 3019..3034, 3036..3058,
		3060..3064, 3066..3075, 3080..3083, 3085, 3086, 3088..3091, 3096..3102, 3104..3107, 3112..3115,
		3117..3123, 3128..3131, 3133..3139, 3142..3155, 3158..3171, 3174..3187, 3190..3269, 3272..3275,
		3277, 3278, 3280..3285, 3288..3291, 3293..3299, 3304..3315, 3320..3323, 3325..3327, 3330, 3332..3343,
		3346, 3348..3359, 3362, 3364..3375, 3378, 3380..3391, 3394, 3396..3407, 3410, 3412..3423, 3426,
		3428..3439, 3442, 3444..3457, 3460..3473, 3476..3487, 3492..3503, 3508..3521, 3524..3537, 3540..3552,
		3556..3568, 3572..3847, 3852..3863, 3868..3879, 3882..3887, 3890, 3892..3895, 3898..4041, 4044..4057,
		4060..4072, 4074..4081, 4084..4088, 4090..4095, 4098, 4100..4111, 4113..4119, 4124..4128, 4130,
		4132..4135, 4138..4143, 4146, 4148..4356, 4359..4372, 4375..4422, 4424..4438, 4440..5381, 5383..5387,
		5389..5396, 5398..5406, 5408..5446, 5448..5454, 5456..6167, 6169, 6171..6184, 6186..6191, 6193..6404,
		6407..6411, 6413, 6414, 6416..6421, 6423..6427, 6429..6436, 6438..6452, 6455..6459, 6461..6470,
		6472..6478, 6480..6486, 6488..6494, 6496..6518, 6520..7167, 7170, 7172..7191, 7196..7199, 7201..7207,
		7210..7215, 7218, 7220..7428, 7431..7444, 7447..7460, 7463..7476, 7479..7494, 7496..7510, 7512..7526,
		7528..7542, 7544..8191, 8194, 8196..8208, 8210, 8212..8215, 8220..8223, 8225..8231, 8234..8239,
		8242, 8244..8322, 8324..8326, 8328..8338, 8340..8342, 8344..8358, 8360..8370, 8372..8383, 8392..8395,
		8397, 8398, 8401, 8403, 8412..8414, 8416, 8418, 8426, 8427, 8429..8431, 8436..8443, 8445..8452,
		8455..8468, 8471..8518, 8520..8534, 8536..8578, 8580..8582, 8584..8594, 8596..8598, 8600..8642,
		8644, 8647..8658, 8660, 8663..9216, 9218, 9220..9239, 9241, 9243..9263, 9265..9346, 9348..9407,
		9409, 9411..9432, 9434, 9436..9456, 9458, 9460..9476, 9479..9483, 9485, 9486, 9488..9493, 9495..9499,
		9501..9531, 9533..9542, 9544..9550, 9552..9558, 9560..9566, 9568..9606, 9608..9614, 9616..9618,
		9620..9626, 9628..9650, 9652..9666, 9668, 9671..9675, 9677, 9678, 9680..9684, 9686..9689, 9691..9694,
		9696..9723, 9725..10239, 10241..10264, 10266, 10268..10279, 10281..10288, 10290, 10293, 10295..10299,
		10301..10418, 10420..10434, 10436..10455, 10457, 10459..10472, 10474..10479, 10481, 10483,
		10484, 10486, 10488..10495, 10497, 10498, 10500, 10501, 10503..10507, 10509..10511, 10513..10516,
		10518..10521, 10523..10526, 10528..10530, 10532, 10533, 10535, 10536, 10538, 10539, 10541..10543,
		10545, 10546, 10548, 10550..10562, 10564..10566, 10568..10574, 10576..10578, 10580..10586,
		10588..10598, 10600..10610, 10612..10626, 10628..10646, 10648..10654, 10656..10658, 10660..10674,
		10676..10678, 10680..10690, 10692..10702, 10704..10706, 10708, 10709, 10711, 10712, 10714,
		10715, 10717..10724, 10726..10738, 10740, 10741, 10743..10747, 10749..11263, 11266, 11272..11275,
		11277, 11278, 11280..11283, 11292..11294, 11296, 11298, 11306, 11307, 11309..11311, 11314,
		11320..11323, 11325..11394, 11396..11398, 11400..11414, 11416..11426, 11428..11430, 11432..11442,
		11444..11446, 11448..11457, 11460, 11461, 11464..11467, 11469, 11470, 11472..11477, 11485..11487,
		11489, 11491, 11498..11503, 11512..11515, 11517..11519, 11521, 11522, 11524..11535, 11537,
		11538, 11540..11551, 11553, 11554, 11556..11567, 11569, 11570, 11572..11586, 11588..11602,
		11604..11618, 11620..11634, 11636..11650, 11652..11666, 11668..11682, 11684..11698, 11700..11714,
		11716..11730, 11732..11746, 11748..11762, 11764..12291, 12296..12299, 12301, 12302, 12304..12307,
		12312..12318, 12320..12323, 12328..12331, 12333..12347, 12349..12418, 12420..12422, 12424..12438,
		12440..12450, 12452..12454, 12456..12466, 12468..12479, 12488..12491, 12493, 12494, 12496,
		12498, 12509..12511, 12513, 12515, 12522..12527, 12532..12539, 12541..12543, 12546, 12548..12559,
		12562, 12564..12610, 12612..12626, 12628..12674, 12676..12678, 12680..12690, 12692..12694,
		12696..12736, 12740, 12743..12752, 12756, 12759..13055, 13058, 13060, 13070, 13072, 13074,
		13076, 13085..13087, 13089..13092, 13094, 13095, 13098..13100, 13102, 13103, 13106..13115,
		13118..13249, 13252, 13253, 13256, 13264, 13265, 13267..13269, 13272, 13276, 13278, 13280..13282,
		13284, 13285, 13288, 13290, 13291, 13293..13297, 13300..13307, 13310..13316, 13318, 13320..13326,
		13328..13331, 13333, 13335..13371, 13373..13446, 13448..13507, 13509, 13511..13515, 13517..13524,
		13526, 13528..13567, 13570, 13572..13583, 13585..13593, 13595..13615, 13618, 13620..13634,
		13636..13650, 13652..13658, 13660..13682, 13684..13698, 13700..13718, 13720..13726, 13728..13746,
		13748..13760, 13764, 13766..13774, 13776, 13778, 13780, 13781, 13783, 13784, 13786, 13787,
		13789..13808, 13812..13819, 13821..13829, 13831, 13832, 13835, 13838, 13840..13845, 13847,
		13848, 13850, 13851, 13853..13871, 13874..13883, 13886..13890, 13892..13894, 13896..13898,
		13900..13902, 13904..13910, 13912..13918, 13920..13962, 13964..13966, 13968..13978, 13980..14002,
		14004..14017, 14019..14021, 14023..14025, 14027, 14032..14041, 14043, 14044, 14046, 14048..14065,
		14067..14075, 14078..14088, 14090, 14092..14103, 14105, 14107..14127, 14129..14140, 14142..14281,
		14283..14296, 14298, 14300..14322, 14324..14331, 14333..14339, 14341, 14343..14347, 14349..14359,
		14361, 14363..14371, 14373, 14375, 14376, 14378..14383, 14385..14388, 14390, 14392..14518,
		14520..14534, 14536..14542, 14544..14552, 14554, 14556..14564, 14566, 14569..14576, 14578,
		14581, 14583..14587, 14589..14591, 14593..14596, 14599..14603, 14605, 14606, 14608, 14610,
		14612, 14613, 14615, 14616, 14618, 14619, 14621..14623, 14625..14628, 14630..14640, 14642,
		14644, 14647..14651, 14653..14658, 14660..14662, 14664..14670, 14672..14678, 14680..14686,
		14688..14690, 14692..14710, 14712..14726, 14728..14734, 14736..14738, 14740..14746, 14748..14758,
		14760..14770, 14772..14774, 14776..14786, 14788, 14789, 14791..14795, 14797, 14798, 14800,
		14801, 14803..14809, 14811..14814, 14816, 14818, 14820, 14821, 14823, 14824, 14826, 14827,
		14829..14833, 14835, 14836, 14839..14843, 14845..14856, 14859, 14861..14873, 14875..14885,
		14887, 14888, 14890, 14891, 14893..14895, 14898, 14900..14904, 14906..14908, 14910..14922,
		14924..14926, 14928..14938, 14940..14950, 14952..14962, 14964..14986, 14988..15026, 15028..15049,
		15051..15054, 15056..15073, 15075..15084, 15086..15089, 15091..15093, 15095..15099, 15101..15111,
		15113, 15115..15128, 15130, 15132..15143, 15145..15152, 15154, 15156, 15157, 15159, 15160,
		15162, 15163, 15165..15306, 15308..15321, 15323..15336, 15338..15345, 15347..15350, 15352..15356,
		15358, 15359, 15362, 15368..15371, 15373, 15374, 15376..15379, 15389..15391, 15393..15395,
		15402..15407, 15410, 15416..15419, 15421..15490, 15492..15494, 15496..15510, 15512..15526,
		15528..15538, 15540..15542, 15544..15553, 15556, 15557, 15560..15563, 15565, 15566, 15568..15573,
		15580..15582, 15584, 15586, 15594, 15595, 15597..15599, 15608..15611, 15613..15620, 15623..15636,
		15639..15652, 15655..15668, 15671..15686, 15688..15702, 15704..15718, 15720..15734, 15736..15750,
		15752..15766, 15768..15782, 15784..15798, 15800..15813, 15815..15829, 15831..15844, 15847..15860,
		15863..16135, 16142, 16144..16151, 16156, 16158, 16160..16165, 16167, 16170, 16171, 16173..16175,
		16178, 16180, 16186, 16187, 16190..16329, 16332, 16333, 16336..16345, 16348, 16349, 16351..16357,
		16359, 16360, 16362..16364, 16366..16369, 16372, 16373, 16376, 16378, 16379, 16382, 16383,
		16386, 16388..16399, 16402, 16404..16408, 16411..16415, 16418, 16420..16424, 16426..16431,
		16434, 16436..16447, 16450..16463, 16466..16479, 16482..16495, 16498..16575, 16580..16591,
		16596..16600, 16603..16607, 16612..16616, 16618..16623, 16628..16708, 16710..16724, 16727..16773,
		16775..16788, 16791..17157, 17159..17163, 17165..17172, 17174..17180, 17182, 17184..17195,
		17197..17212, 17214..17356, 17358, 17360..17365, 17367..17371, 17373, 17375..17388, 17390..17403,
		17405..17407, 17410, 17412..17432, 17434..17455, 17458, 17460..17471, 17474..17519, 17522..17599,
		17604..17625, 17627..17647, 17652..17732, 17735..17739, 17741, 17742, 17744..17749, 17751..17755,
		17757..17787, 17789..17796, 17799..17803, 17805, 17806, 17808..17812, 17814..17822, 17824..17851,
		17853..17983, 17985..17993, 17995..18032, 18034..18056, 18058..18097, 18099..18188, 18190,
		18192..18235, 18237..18373, 18375..18379, 18381, 18383..18428, 18430, 18431, 18434, 18436..18457,
		18459..18472, 18474..18479, 18482, 18484..18495, 18498..18543, 18546..18625, 18628..18648,
		18650..18671, 18676..18756, 18759..18763, 18765, 18766, 18768..18772, 18774..18782, 18784..18789,
		18791..18795, 18797..18804, 18807..18811, 18813..18821, 18823..18827, 18829, 18830, 18832..18837,
		18839..18843, 18845..18852, 18854..18868, 18871..18875, 18877..19016, 19018..19055, 19057..19081,
		19083..19122, 19124..19128, 19130..19252, 19254..19260, 19262..19445, 19447..19451, 19453..19455,
		19458, 19460..19480, 19483..19487, 19490, 19492..19496, 19498..19503, 19506, 19508..19519,
		19522..19551, 19554..19567, 19570..19649, 19652..19672, 19675..19679, 19684..19688, 19690..19695,
		19700..19781, 19783..19796, 19799..19812, 19815..19828, 19830..19861, 19863..19876, 19879..19893,
		19895..20236, 20238, 20240..20251, 20253..20268, 20270..20277, 20279..20283, 20285..20429,
		20431..20446, 20448..20453, 20455..20459, 20461..20476, 20478..20483, 20488..20491, 20493,
		20494, 20496..20499, 20504..20507, 20509, 20510, 20512..20515, 20520..20523, 20525..20539,
		20541..20675, 20680..20683, 20685, 20686, 20688..20691, 20696..20699, 20701, 20702, 20704..20707,
		20712..20715, 20717..20731, 20733..20735, 20738, 20740..20751, 20754, 20756..20802, 20804..20818,
		20820..20866, 20868..20882, 20884..20928, 20932..20944, 20948..21247, 21249..21255, 21257,
		21259..21264, 21266, 21268..21272, 21274, 21276..21279, 21281..21287, 21289..21296, 21298..21442,
		21444..21448, 21450, 21452..21457, 21459..21465, 21467..21474, 21476..21480, 21482..21489,
		21491..21508, 21510, 21512..21515, 21517, 21518, 21520..21524, 21526, 21528..21563, 21565..21699,
		21701, 21703..21707, 21709, 21710, 21712..21715, 21717, 21719..21755, 21757..21759, 21762,
		21764..21776, 21778, 21780..21784, 21786..21807, 21810, 21812..21826, 21828..21874, 21876..21890,
		21892..21906, 21908..21914, 21916..21938, 21940..21952, 21956..21969, 21971..21977, 21979..22000,
		22004..22028, 22030, 22032..22075, 22077..22158, 22160..22213, 22215..22219, 22221, 22223..22268,
		22270..22280, 22282, 22284..22319, 22321..22473, 22475..22514, 22516..22531, 22533, 22535..22539,
		22541, 22542, 22544..22564, 22566, 22568..22580, 22582, 22584..22587, 22589..22726, 22728..22731,
		22733, 22734, 22736..22755, 22757, 22759..22771, 22773, 22775..22779, 22781..22783, 22786,
		22788..22799, 22801..22809, 22811..22816, 22818, 22820..22824, 22826..22831, 22834, 22836..22850,
		22852..22866, 22868..22874, 22876..22898, 22900..22914, 22916..22946, 22948..22962, 22964..22977,
		22980..22994, 22996..23000, 23002..23009, 23011..23024, 23028..23051, 23053..23100, 23102..23118,
		23120..23246, 23248..23285, 23287..23291, 23293..23303, 23305, 23307..23344, 23346, 23348..23352,
		23354..23498, 23500..23537, 23539..23555, 23560..23563, 23565, 23566, 23568..23571, 23576..23579,
		23581, 23582, 23584..23587, 23592..23595, 23597..23603, 23608..23611, 23613..23749, 23752..23755,
		23757, 23758, 23760..23765, 23768..23771, 23773, 23774, 23776..23779, 23784..23787, 23789..23795,
		23800..23803, 23805..23807, 23810, 23812..23823, 23826, 23828..23839, 23842, 23844..23855,
		23858, 23860..23874, 23876..23890, 23892..23906, 23908..23922, 23924..23938, 23940..23954,
		23956..23970, 23972..23986, 23988..24001, 24004..24017, 24020..24032, 24036..24048, 24052..24328,
		24330, 24332..24343, 24345, 24347..24360, 24362..24367, 24369..24375, 24377..24521, 24523..24538,
		24540..24562, 24564..24568, 24570..24579, 24584..24587, 24589, 24590, 24592..24595, 24600..24603,
		24605, 24606, 24608..24611, 24616..24619, 24621..24635, 24637..24706, 24708..24710, 24712..24722,
		24724..24726, 24728..24738, 24740..24742, 24744..24754, 24756..24767, 24776..24779, 24781,
		24782, 24797, 24798, 24810, 24811, 24813..24815, 24820..24827, 24829..24898, 24900..24914,
		24916..24962, 24964..24978, 24980..24982, 24984..25025, 25027..25041, 25043..25045, 25047..25344,
		25346, 25348, 25349, 25351, 25352, 25354, 25357..25359, 25361..25364, 25366, 25369, 25371,
		25372, 25374, 25376, 25378..25384, 25386, 25387, 25389..25391, 25393..25404, 25406..25537,
		25539..25542, 25544, 25545, 25547, 25548, 25550, 25552..25554, 25556, 25557, 25559, 25560,
		25562, 25565, 25567..25569, 25571..25574, 25576..25580, 25582..25586, 25588..25595, 25597..25603,
		25605, 25607..25611, 25613, 25614, 25616..25619, 25621, 25623..25659, 25661..25730, 25732..25778,
		25780..25791, 25796, 25798, 25800..25803, 25805, 25806, 25808..25812, 25814, 25817, 25819..25839,
		25844..25851, 25853..25922, 25924..25938, 25940..25946, 25948..25970, 25972..25986, 25988..25990,
		25992..25998, 26000..26006, 26008..26014, 26016..26034, 26036..26049, 26051..26053, 26055..26059,
		26061, 26062, 26064..26069, 26071..26075, 26077..26097, 26099..26107, 26109..26117, 26119..26123,
		26125..26172, 26174..26182, 26184..26190, 26192..26250, 26252..26305, 26307..26313, 26315,
		26316, 26318, 26320..26363, 26365..26375, 26377, 26379, 26380, 26382, 26384..26416, 26418..26427,
		26429..26565, 26567, 26568, 26570, 26573, 26575..26609, 26611..26620, 26622, 26623, 26626,
		26628..26647, 26649, 26651..26664, 26666..26671, 26674, 26676..26754, 26756..26802, 26804..26817,
		26820..26840, 26842, 26844..26855, 26857..26863, 26868..26950, 26952..26958, 26960..26966,
		26968..26974, 26976..26998, 27000..27014, 27016..27022, 27024..27046, 27048..27062, 27064..27077,
		27079..27083, 27085, 27086, 27088..27102, 27104..27109, 27111..27115, 27117..27125, 27127..27131,
		27133..27145, 27147..27210, 27212..27314, 27316..27377, 27379..27444, 27446, 27448..27452,
		27454..27637, 27639..27643, 27645..27647, 27650, 27653, 27655..27659, 27661..27668, 27670,
		27676..27678, 27682, 27685, 27687, 27690, 27691, 27693..27695, 27698, 27700, 27702, 27704..27778,
		27780..27798, 27800..27810, 27812..27826, 27828..27830, 27832..27841, 27844..27846, 27848..27854,
		27856..27861, 27863, 27869..27871, 27876, 27878, 27882..27887, 27893, 27895..27899, 27901..27990,
		27992..28006, 28008..28022, 28024..28038, 28040..28054, 28056..28070, 28072..28101, 28103..28117,
		28119..28133, 28135..28423, 28425, 28427, 28428, 28430, 28432..28440, 28442, 28445..28455,
		28457..28460, 28462..28464, 28466, 28468, 28469, 28471, 28472, 28474, 28475, 28477..28618,
		28620, 28621, 28623..28633, 28635..28638, 28640..28645, 28647, 28648, 28650, 28651, 28653..28657,
		28659..28662, 28664..28668, 28670..28802, 28804..28806, 28808..28818, 28820..28822, 28824..28834,
		28836..28838, 28840..28850, 28852..28863, 28868, 28871..28875, 28877, 28878, 28884, 28887,
		28888, 28891, 28893, 28894, 28900, 28903, 28904, 28906, 28907, 28909..28911, 28916..28923,
		28925..29058, 29060..29074, 29076..29439, 29441..29444, 29446..29449, 29451, 29452, 29454,
		29456, 29458, 29460, 29461, 29463, 29464, 29466, 29467, 29469..29471, 29473..29476, 29478..29484,
		29486..29488, 29490..29499, 29501..29634, 29636, 29637, 29639, 29640, 29642, 29643, 29645,
		29647..29649, 29651..29657, 29659, 29660, 29662, 29664..29666, 29668, 29669, 29671, 29672,
		29674, 29675, 29677..29681, 29683..29692, 29694..29826, 29828..29830, 29832..29846, 29848..29874,
		29876..29887, 29892, 29893, 29895..29899, 29901, 29902, 29904..29909, 29911, 29912, 29914..29935,
		29940..29947, 29949..30030, 30032..30046, 30048..30082, 30084..30094, 30096..30098, 30100..30130,
		30132..30274, 30276..30350, 30352..30386, 30388..30469, 30471, 30472, 30474, 30475, 30477..30511,
		30513..30524, 30526..30665, 30667, 30668, 30670, 30672..30706, 30708..30715, 30717..30886,
		30888..30902, 30904..30923, 30925, 30926, 30928..30949, 30951..30965, 30967..30971, 30973..31042,
		31044..31058, 31060..31090, 31092..31106, 31108..31138, 31140..31154, 31156..31310, 31312..31497,
		31499..31536, 31538, 31540..31544, 31546..31729, 31731..31878, 31880..31894, 31896..31910,
		31912..31922, 31924..31926, 31928..31938, 31940, 31941, 31943..31947, 31949, 31950, 31952..31957,
		31959..31961, 31963, 31965, 31966, 31968, 31970, 31972, 31975, 31976, 31978, 31979, 31981..31983,
		31985, 31987, 31988, 31991..31995, 31997..32066, 32068..32082, 32084..32098, 32100..32114,
		32116..32130, 32132..32146, 32148..32162, 32164..32178, 32180..32520, 32522, 32523, 32525..32537,
		32539, 32540, 32542, 32544..32549, 32551, 32552, 32554, 32555, 32557..32559, 32561..32564,
		32566..32572, 32574..32713, 32715..32718, 32720..32733, 32735..32748, 32750..32754, 32756,
		32757, 32759, 32760, 32762, 32763, 32765..32767, 32769..32784, 32786, 32788..32792, 32794..32799,
		32801..32816, 32818, 32820..32832, 32834..32847, 32849..32864, 32866..32879, 32881..32960,
		32962, 32964..32975, 32977, 32979..32985, 32987..32992, 32994, 32996..33000, 33002..33007,
		33009, 33011..33156, 33158..33172, 33175..33343, 33346, 33348, 33350..33353, 33355, 33358,
		33362, 33364, 33367, 33368, 33371, 33374, 33376..33409, 33412, 33413, 33415, 33416, 33418,
		33419, 33424, 33425, 33428, 33429, 33431, 33432, 33435, 33440..33535, 33538, 33540, 33543,
		33544, 33547, 33550, 33554, 33556, 33559, 33560, 33563, 33566, 33570..33572, 33574..33576,
		33578, 33579, 33582, 33583, 33586..33595, 33598, 33599, 33602, 33603, 33606, 33607, 33610,
		33611, 33614, 33615, 33618, 33619, 33622, 33623, 33626, 33627, 33630, 33631, 33634, 33635,
		33638, 33639, 33642, 33643, 33646, 33647, 33650..33659, 33662..33729, 33732, 33733, 33735,
		33736, 33739, 33744, 33745, 33748, 33749, 33751, 33752, 33755, 33760, 33761, 33764, 33765,
		33767, 33768, 33770, 33771, 33774..33777, 33780..33787, 33790..33792, 33794, 33796..33817,
		33819..33839, 33841..33855, 33857..33904, 33906..33983, 33985, 33987..34008, 34010..34032,
		34034, 34036..34180, 34183..34187, 34189, 34190, 34192..34197, 34199..34203, 34205..34235,
		34237..34367, 34370, 34372, 34375, 34376, 34379, 34382, 34384..34389, 34391, 34392, 34394,
		34395, 34397..34415, 34418..34427, 34430..34433, 34435..34437, 34439, 34440, 34443, 34448..34457,
		34459, 34460, 34462, 34464..34481, 34484..34491, 34494..34572, 34574, 34576..34581, 34583,
		34584, 34586..34608, 34610..34619, 34622..34635, 34637..34644, 34646, 34647, 34649..34671,
		34673..34683, 34686..34763, 34765, 34767..34777, 34779..34801, 34803..34811, 34814..35201,
		35204..35217, 35219..35225, 35227..35232, 35234, 35236..35240, 35242..35247, 35252..35403,
		35406, 35408..35429, 35431..35435, 35437..35444, 35447..35451, 35454..35469, 35472..35500,
		35502..35509, 35511..35515, 35518..35593, 35595..35609, 35611..35624, 35626..35631, 35634,
		35636..35640, 35642..35656, 35658..35672, 35674..35687, 35689..35695, 35698..35703, 35705..35825,
		35828..35839, 35841..35844, 35847..35851, 35853, 35854, 35856..35860, 35863, 35864, 35866,
		35867, 35869, 35870, 35873..35876, 35879..35883, 35885..35888, 35890, 35892, 35895..35899,
		35901..35904, 35906, 35907, 35910..35923, 35926..35936, 35938, 35939, 35942..35951, 35953..35955,
		35958..36037, 36039..36043, 36045, 36046, 36048..36053, 36055..36059, 36061, 36062, 36064..36068,
		36071..36075, 36077..36084, 36087..36091, 36093..36225, 36228..36241, 36244..36255, 36260..36271,
		36276..36427, 36430, 36432..36443, 36446, 36448..36452, 36455..36459, 36462..36468, 36470..36475,
		36478..36493, 36496..36509, 36512..36517, 36519..36523, 36526..36533, 36535..36539, 36542..36616,
		36619, 36621..36632, 36635, 36636, 36638, 36640..36645, 36647, 36648, 36650, 36651, 36653..36655,
		36658, 36660, 36662..36664, 36666..36668, 36670..36679, 36682..36684, 36686..36695, 36698,
		36699, 36701..36708, 36710, 36711, 36714..36716, 36718, 36719, 36722, 36723, 36725..36727,
		36730, 36731, 36733..36809, 36811..36814, 36816..36825, 36827..36829, 36831..36840, 36842..36844,
		36846..36849, 36852, 36853, 36855, 36856, 36858, 36859, 36861..36867, 36872..36875, 36877,
		36878, 36880..36883, 36888..36891, 36893, 36894, 36896..36899, 36904..36907, 36909..36923,
		36925..37059, 37064..37067, 37069, 37070, 37072..37075, 37080..37083, 37085, 37086, 37088..37091,
		37096..37099, 37101..37115, 37117..37119, 37122, 37124..37135, 37138, 37140..37186, 37188..37202,
		37204..37250, 37252..37266, 37268..37312, 37316..37328, 37332..37375, 37378, 37380..37385,
		37387, 37390, 37394, 37396, 37397, 37399, 37400, 37403, 37406, 37408..37442, 37444..37450,
		37452..37454, 37456..37458, 37460..37462, 37464..37466, 37468..37470, 37472..37506, 37508..37518,
		37520..37522, 37524..37530, 37532..37534, 37536..37569, 37571..37573, 37575..37579, 37584,
		37585, 37587..37589, 37591..37593, 37595, 37600..37631, 37634, 37636, 37646, 37650, 37652,
		37662, 37666..37668, 37670, 37671, 37674, 37675, 37678, 37679, 37682..37691, 37694..37825,
		37828, 37829, 37832, 37840, 37841, 37844, 37845, 37848, 37856, 37857, 37860, 37861, 37864,
		37866, 37867, 37870..37873, 37876..37883, 37886..37902, 37904..37907, 37909, 37911..37947,
		37949..38091, 38093..38100, 38102, 38104..38143, 38146, 38148..38159, 38161..38169, 38171..38191,
		38194, 38196..38210, 38212..38226, 38228..38234, 38236..38258, 38260..38274, 38276..38322,
		38324..38336, 38340..38352, 38354, 38356..38360, 38362..38384, 38388..38405, 38407, 38408,
		38411, 38414, 38416..38421, 38423, 38424, 38426, 38427, 38429..38447, 38450..38459, 38462..38466,
		38468..38470, 38472..38474, 38476..38478, 38480..38486, 38488..38494, 38496..38538, 38540..38542,
		38544..38554, 38556..38578, 38580..38593, 38595..38597, 38599..38601, 38603, 38608..38617,
		38619, 38620, 38622, 38624..38641, 38643..38651, 38654..38663, 38665, 38667..38679, 38681,
		38683..38703, 38706..38716, 38718..38856, 38858, 38860..38872, 38874, 38876..38897, 38900..38907,
		38909..38935, 38937, 38939..38952, 38954..38959, 38962, 38964..39128, 39130, 39132..39143,
		39145..39151, 39156..39172, 39175..39179, 39181, 39182, 39184..39189, 39191..39195, 39197..39204,
		39206..39220, 39223..39227, 39229..39238, 39240..39246, 39248..39254, 39256..39262, 39264..39286,
		39288..39302, 39304..39310, 39312..39334, 39336..39350, 39352..39365, 39367..39371, 39373,
		39374, 39376..39390, 39392..39397, 39399..39403, 39405..39412, 39415..39419, 39421..39432,
		39435..39449, 39451..39464, 39466..39471, 39474, 39476..39480, 39482..39498, 39500..39514,
		39516..39538, 39540..39562, 39564..39602, 39604..39625, 39627..39649, 39651..39665, 39667..39732,
		39734, 39736..39739, 39742..39925, 39927..39931, 39934, 39935, 39938, 39941, 39943..39947,
		39949..39956, 39958, 39964..39966, 39970, 39973, 39975, 39978, 39979, 39981..39983, 39986,
		39988, 39990, 39992..40129, 40132..40151, 40156..40159, 40164..40167, 40170..40175, 40180..40196,
		40198..40212, 40215..40228, 40231..40245, 40247..40278, 40280..40294, 40296..40310, 40312..40326,
		40328..40342, 40344..40358, 40360..40389, 40391..40405, 40407..40420, 40423..40436, 40438..40456,
		40458..40472, 40475..40488, 40490..40495, 40498, 40500..40538, 40540..40546, 40548..40562,
		40564..40586, 40588..40602, 40604..40626, 40628..40649, 40651..40665, 40667..40673, 40675..40689,
		40691..40711, 40713, 40715, 40718, 40720..40728, 40730, 40734, 40736..40741, 40743, 40745..40747,
		40750..40752, 40754, 40756, 40760, 40762, 40763, 40766..40906, 40908, 40909, 40912..40921,
		40923..40925, 40928..40933, 40935, 40936, 40938, 40939, 40942..40945, 40947..40949, 40952..40955,
		40958..41090, 41092..41106, 41108..41122, 41124..41138, 41140..41152, 41154, 41156..41167,
		41169, 41171..41175, 41177, 41179..41184, 41186, 41188..41192, 41194..41199, 41201, 41203..41350,
		41352..41366, 41368..41497, 41499..41538, 41540..41554, 41556..41562, 41564..41602, 41604..41610,
		41612..41614, 41616..41618, 41620..41626, 41628..41630, 41632..41665, 41667..41673, 41675,
		41680, 41681, 41683..41685, 41687..41689, 41691, 41696..41732, 41736..41739, 41742, 41744..41748,
		41752..41755, 41758, 41760..41764, 41766..41771, 41774..41787, 41790..41858, 41860..41862,
		41864..41866, 41868..41870, 41872..41874, 41876..41878, 41880..41882, 41884..41886, 41888..41890,
		41892..41894, 41896..41906, 41908..41921, 41924, 41925, 41928, 41936, 41937, 41940, 41941,
		41944, 41952, 41953, 41956, 41957, 41960, 41962, 41963, 41966..41969, 41972..41979, 41982..42114,
		42116..42175, 42177, 42179..42200, 42202, 42204..42224, 42226, 42228..42374, 42376..42382,
		42384..42505, 42507..42521, 42523..42562, 42564..42570, 42572..42586, 42588..42634, 42636..42638,
		42640..42654, 42656..42674, 42676..42689, 42691..42693, 42695..42697, 42699, 42704..42709,
		42711..42715, 42717, 42719..42737, 42739..42747, 42750..42764, 42766, 42768..42773, 42775..42811,
		42814..42894, 42896..42906, 42908..42930, 42932..42955, 42957, 42959..42969, 42971..42993,
		42995..43003, 43006..43190, 43192..43394, 43396..43426, 43428..43442, 43444..43531, 43534,
		43536..43564, 43566..43573, 43575..43579, 43582..43598, 43600..43638, 43640..43662, 43664..43725,
		43728..43749, 43751..43755, 43757..43765, 43767..43771, 43774..43783, 43785, 43787..43799,
		43801, 43803..43816, 43818..43823, 43826, 43828..43832, 43834..43954, 43956..43978, 43980..43994,
		43996..44017, 44020..44166, 44168..44182, 44184..44198, 44200..44210, 44212..44214, 44216..44226,
		44228, 44229, 44232..44235, 44237, 44238, 44240..44245, 44249, 44251, 44253, 44254, 44256,
		44258, 44264, 44266, 44267, 44269..44271, 44273, 44275, 44280..44283, 44285..44418, 44420..44434,
		44436..44450, 44452..44466, 44468..44555, 44558, 44560..44571, 44574, 44576..44581, 44583..44587,
		44590..44597, 44599..44603, 44606..44622, 44624..44638, 44640..44646, 44648..44662, 44664..44686,
		44688..44702, 44704..44749, 44752..44765, 44768..44773, 44775..44779, 44782..44795, 44798..44807,
		44813..44823, 44828, 44830, 44832..44837, 44839, 44842, 44843, 44845..44847, 44850, 44852,
		44854, 44858..44860, 44862..44938, 44940..44954, 44956..44958, 44960..44978, 44980..44982,
		44984..45001, 45004..45006, 45008..45017, 45020, 45021, 45023..45032, 45034..45036, 45038..45041,
		45044, 45045, 45047, 45048, 45050, 45051, 45053..45190, 45192..45206, 45208..45222, 45224..45442,
		45444..45458, 45460..45698, 45700..45710, 45712..45714, 45716..45726, 45728..45823, 45826,
		45828..45832, 45835..45839, 45842, 45844..45848, 45851..45855, 45858..45864, 45866..45871,
		45874..45954, 45956..45958, 45960..45962, 45964..45966, 45968..45970, 45972..45974, 45976..45978,
		45980..45982, 45984..45986, 45988..45990, 45992..46002, 46004..46017, 46020, 46021, 46023,
		46024, 46027, 46032, 46033, 46036, 46037, 46039, 46040, 46043, 46048, 46049, 46052, 46053,
		46055, 46056, 46058, 46059, 46062..46065, 46068..46075, 46078..46466, 46468..46514, 46516..46734,
		46736..46770, 46772..46857, 46859..46873, 46875..46895, 46898..47026, 47028..47048, 47050..47064,
		47066..47089, 47092..47099, 47101..47282, 47284..47502, 47504..47794, 47796..47924, 47926..47931,
		47934..48054, 48056..48117, 48119..48123, 48126..48258, 48260..48278, 48280..48290, 48292..48306,
		48308..48310, 48312..48818, 48820..48905, 48907, 48910, 48912..48920, 48922, 48923, 48926,
		48928..48933, 48935..48939, 48942..48944, 48946, 48948, 48951, 48952, 48954, 48955, 48958..49038,
		49040..49050, 49052..49054, 49056..49074, 49076..49078, 49080..49101, 49104..49113, 49115..49117,
		49120..49125, 49127, 49128, 49130, 49131, 49134..49137, 49139..49141, 49143..49147, 49150..49155,
		49157, 49159..49163, 49165..49172, 49174, 49176..49182, 49184..49187, 49189, 49191..49195,
		49197..49220, 49222..49235, 49237..49252, 49254..49348, 49350, 49352..49358, 49360..49363,
		49365, 49367..49371, 49373..49380, 49382, 49384..49403, 49405..49472, 49474, 49476..49487,
		49489..49535, 49540..49551, 49556..49617, 49619..49669, 49671..49673, 49675, 49678, 49680..49685,
		49687..49689, 49691, 49694, 49696..49727, 49730, 49742, 49746, 49758, 49760..49793, 49796,
		49797, 49799, 49808, 49809, 49812, 49813, 49815, 49824..49857, 49859..49861, 49863..49865,
		49867, 49872, 49873, 49875..49877, 49879..49881, 49883, 49888..49919, 49922, 49924, 49926,
		49932, 49934, 49936, 49938, 49940, 49941, 49943, 49949..49951, 49953..49956, 49958, 49959,
		49962..49964, 49966, 49967, 49970..49979, 49981..49983, 49986, 49987, 49989..49991, 49994,
		49995, 49997..49999, 50001..50004, 50006, 50007, 50010..50012, 50014..50016, 50018, 50019,
		50021..50023, 50026, 50027, 50029..50031, 50034..50044, 50046..50113, 50116, 50117, 50119,
		50120, 50125, 50127..50129, 50131..50134, 50136, 50140, 50142, 50144..50146, 50148, 50149,
		50151, 50152, 50154, 50155, 50157..50161, 50164..50172, 50174..50180, 50182, 50184..50190,
		50192..50195, 50197, 50199..50235, 50237..50243, 50245..50260, 50262..50371, 50373, 50375..50379,
		50381..50388, 50390, 50392..50495, 50497..50512, 50514, 50516..50520, 50522, 50524..50544,
		50546, 50548..50559, 50564..50575, 50577, 50579..50583, 50585, 50587..50607, 50612..50625,
		50627..50693, 50695..50697, 50699, 50702, 50704..50709, 50711..50715, 50717..50747, 50750,
		50751, 50754, 50766, 50768..50772, 50774, 50777, 50779, 50780, 50782, 50784..50799, 50802..50811,
		50814..50817, 50819..50821, 50823, 50832..50837, 50839, 50840, 50842, 50845, 50847..50865,
		50868..50875, 50878..50881, 50883..50885, 50887..50889, 50891, 50896..50905, 50907, 50908,
		50910, 50912..50929, 50931..50939, 50942..50952, 50954, 50956..50967, 50969, 50971..50991,
		50993..51004, 51006..51015, 51017..51032, 51034..51056, 51058..51067, 51069..51145, 51147..51160,
		51162, 51164..51186, 51188..51195, 51197..51203, 51205, 51207..51211, 51213..51235, 51237,
		51239..51252, 51254, 51256..51268, 51270..51300, 51302..51315, 51317..51520, 51522, 51524..51535,
		51537..51543, 51545, 51547..51552, 51554, 51556..51560, 51562..51567, 51569..51590, 51592..51598,
		51600..51605, 51607..51611, 51613..51620, 51622, 51624..51637, 51639..51643, 51645..51721,
		51723, 51725..51737, 51739..51749, 51751..51755, 51757..51772, 51774..51783, 51788, 51790,
		51792..51800, 51802, 51804..51807, 51809..51812, 51814, 51817..51820, 51822, 51823, 51826,
		51829, 51831, 51834, 51835, 51837..51849, 51852, 51853, 51855..51865, 51867..51877, 51879,
		51880, 51882, 51883, 51885..51889, 51892..51895, 51898..51900, 51902..51913, 51915..51918,
		51920..51937, 51939..51948, 51950..51953, 51955..51957, 51959..51963, 51965..51975, 51977,
		51979..51992, 51994, 51996..52007, 52009..52016, 52018, 52020, 52021, 52023, 52024, 52026,
		52027, 52029..52040, 52042..52055, 52057..52072, 52074..52079, 52081..52084, 52086, 52087,
		52089..52092, 52094..52170, 52172..52185, 52187..52200, 52202..52209, 52211..52214, 52216..52220,
		52222, 52223, 52226, 52232..52235, 52237, 52238, 52240..52243, 52253..52255, 52257..52259,
		52266..52271, 52274, 52280..52283, 52285..52287, 52290, 52291, 52294..52307, 52310..52320,
		52322, 52323, 52326..52335, 52338, 52339, 52342..52417, 52420..52439, 52444..52448, 52450,
		52452..52455, 52458..52463, 52468..52547, 52552..52563, 52568..52579, 52584..52595, 52600..52613,
		52616..52629, 52632..52644, 52648..52660, 52664..52677, 52679..52693, 52695..52709, 52711..52725,
		52727..52745, 52747..52761, 52763..52807, 52812..52823, 52828..52831, 52834, 52836..52839,
		52842..52847, 52850, 52852..52855, 52858..52873, 52876..52889, 52892..52897, 52899..52903,
		52906..52913, 52916..52919, 52922..52937, 52939..52953, 52955..52961, 52963..52977, 52979..52999,
		53006, 53008..53015, 53020, 53022, 53024..53029, 53031, 53034, 53035, 53037..53039, 53042,
		53044, 53050, 53051, 53054..53063, 53066, 53067, 53070..53079, 53082, 53083, 53085..53091,
		53094, 53095, 53098..53100, 53102, 53103, 53106, 53107, 53110, 53111, 53114, 53115, 53118..53193,
		53196, 53197, 53200..53209, 53212, 53213, 53215..53221, 53223, 53224, 53226..53228, 53230..53233,
		53236, 53237, 53240, 53242, 53243, 53246, 53247, 53249..53264, 53266, 53268..53272, 53274,
		53276..53279, 53281..53287, 53289..53296, 53298, 53300..53508, 53511..53524, 53527..53574,
		53576..53590, 53592..53759, 53761, 53762, 53764, 53765, 53767, 53768, 53771, 53773, 53774,
		53777, 53778, 53780, 53781, 53783, 53784, 53787, 53789, 53790, 53792..53826, 53828..53830,
		53832..53834, 53836..53838, 53840..53842, 53844..53846, 53848..53850, 53852..53854, 53856..54016,
		54018, 54020, 54024, 54026, 54030, 54033..54036, 54041, 54043, 54044, 54046, 54048, 54050..54052,
		54054..54056, 54058, 54059, 54061..54063, 54065..54075, 54078..54272, 54274, 54276..54295,
		54297, 54299..54319, 54321..54532, 54535..54539, 54541, 54542, 54544..54549, 54551..54555,
		54557..54587, 54589..54598, 54600..54606, 54608..54614, 54616..54622, 54624..54789, 54791,
		54792, 54795, 54797, 54798, 54800..54809, 54811..54814, 54816..54831, 54833..54843, 54845..54850,
		54852..54854, 54856..54858, 54860..54862, 54864..54874, 54876..55047, 55049, 55051, 55052,
		55054, 55056..55061, 55063, 55064, 55066, 55068..55088, 55090..55099, 55101..55295, 55297..55320,
		55322, 55324..55335, 55337..55344, 55346, 55348..55554, 55556, 55557, 55559..55563, 55565..55567,
		55569..55572, 55574..55577, 55579..55582, 55584..55586, 55588, 55589, 55591, 55592, 55594,
		55595, 55597..55599, 55601..55604, 55606..55622, 55624..55630, 55632..55634, 55636..55642,
		55644..55654, 55656..55666, 55668..55817, 55819, 55821, 55822, 55824..55832, 55834..55858,
		55860, 55861, 55863, 55864, 55866, 55867, 55869..55882, 55884..55886, 55888..55906, 55908..55926,
		55928..56072, 56074, 56076..56087, 56089, 56091..56104, 56106..56111, 56113..56116, 56118,
		56121..56124, 56126..56319, 56322, 56328..56331, 56333, 56334, 56336..56339, 56348..56350,
		56352, 56354, 56362, 56363, 56365..56367, 56370, 56376..56379, 56381..56575, 56577, 56578,
		56580..56591, 56593, 56594, 56596..56607, 56609, 56610, 56612..56623, 56625, 56626, 56628..56642,
		56644..56658, 56660..56674, 56676..56690, 56692..56843, 56845, 56846, 56848..56859, 56861,
		56862, 56864..56869, 56871..56875, 56877..56885, 56887..56891, 56893..56910, 56912..56926,
		56928..56934, 56936..56950, 56952..57095, 57102, 57104..57111, 57117..57125, 57127, 57130..57132,
		57134, 57135, 57138, 57140, 57146, 57147, 57150..57494, 57496..57540, 57542, 57544..57550,
		57552..57555, 57557, 57559..57563, 57565..57572, 57574, 57576..57595, 57597..57730, 57732..57746,
		57748..57861, 57863..57867, 57869, 57870, 57872..57877, 57879..57883, 57885, 57886, 57888..57926,
		57928..57934, 57936..57942, 57944..57950, 57952..57986, 57988..57994, 57996..57998, 58000..58002,
		58004..58010, 58012..58014, 58016..58053, 58055..58057, 58059, 58061, 58062, 58064..58069,
		58071..58073, 58075, 58077, 58078, 58080..58111, 58114, 58116..58119, 58124..58128, 58130,
		58132..58135, 58140..58143, 58145..58151, 58154..58159, 58162..58242, 58244..58246, 58248..58250,
		58252..58254, 58256..58258, 58260..58266, 58268..58278, 58280..58290, 58292..58305, 58308,
		58309, 58311, 58312, 58317, 58319..58321, 58323..58326, 58328, 58332, 58334, 58336..58338,
		58340, 58341, 58343, 58344, 58346, 58347, 58349..58353, 58356..58364, 58366..58502, 58504..58563,
		58565, 58567..58571, 58573..58580, 58582, 58584..58754, 58756..58802, 58804..58885, 58887..58891,
		58893, 58894, 58896..58901, 58903..58907, 58909..58939, 58941..58950, 58952..58958, 58960..58966,
		58968..58974, 58976..59018, 59020..59022, 59024..59034, 59036..59058, 59060..59077, 59079..59081,
		59083, 59085, 59086, 59088..59097, 59099..59102, 59104..59131, 59133..59144, 59146, 59148..59159,
		59161, 59163..59183, 59185..59274, 59276..59337, 59339..59352, 59354, 59356..59378, 59380..59387,
		59389..59574, 59576..59590, 59592..59598, 59600..59620, 59622, 59624..59635, 59637, 59639..59643,
		59645..59782, 59784..59790, 59792..59794, 59796..59802, 59804..59814, 59816..59826, 59828..59865,
		59867..59913, 59915, 59917..59929, 59931..59941, 59943..59947, 59949..59978, 59980..59982,
		59984..59994, 59996..60006, 60008..60018, 60020..60042, 60044..60082, 60084..60105, 60107..60110,
		60112..60149, 60151..60155, 60157..60167, 60169, 60171..60184, 60186, 60188..60199, 60201..60208,
		60210, 60212, 60213, 60215, 60216, 60218, 60219, 60221..60314, 60316..60338, 60340..60362,
		60364..60377, 60379..60392, 60394..60401, 60403..60406, 60408..60412, 60414..60546, 60548..60550,
		60552..60566, 60568..60582, 60584..60594, 60596..60598, 60600..60609, 60612, 60613, 60616..60619,
		60621, 60622, 60624..60629, 60636..60638, 60640, 60642, 60650, 60651, 60653..60655, 60664..60667,
		60669..60806, 60808..60822, 60824..60838, 60840..60854, 60856..60869, 60871..60885, 60887..60901,
		60903..60917, 60919..60937, 60939..60953, 60955..61002, 61004..61018, 61020..61026, 61028..61042,
		61044..61066, 61068..61082, 61084..61106, 61108..61129, 61131..61145, 61147..61191, 61198,
		61200..61207, 61212, 61214, 61216..61221, 61223, 61226, 61227, 61229..61231, 61234, 61236,
		61242, 61243, 61246..61322, 61324..61326, 61328..61338, 61340..61342, 61344..61362, 61364..61366,
		61368..61385, 61388, 61389, 61392..61401, 61404, 61405, 61407..61413, 61415, 61416, 61418..61420,
		61422..61425, 61428, 61429, 61432, 61434, 61435, 61438..61586, 61588..61618, 61620..61632,
		61634, 61636..61647, 61649, 61651..61655, 61657, 61659..61664, 61666, 61668..61672, 61674..61679,
		61681, 61683..61830, 61832..61846, 61848..61909, 61911..62018, 62020..62026, 62028..62034,
		62036..62042, 62044..62082, 62084..62090, 62092..62094, 62096..62098, 62100..62106, 62108..62110,
		62112..62145, 62147..62149, 62151..62153, 62155, 62160, 62161, 62163..62165, 62167..62169,
		62171, 62176..62212, 62216..62219, 62222, 62224..62228, 62232..62236, 62238, 62240..62244,
		62246..62251, 62253..62267, 62270..62338, 62340..62342, 62344..62346, 62348..62350, 62352..62358,
		62360..62366, 62368..62370, 62372..62374, 62376..62401, 62403..62405, 62408, 62409, 62411,
		62416..62418, 62420, 62421, 62424, 62426, 62429, 62431..62433, 62435..62437, 62440..62444,
		62446..62450, 62452..62459, 62462..62594, 62596..62655, 62657, 62659..62680, 62682, 62684..62704,
		62706, 62708..62854, 62856..62862, 62864..62917, 62919..62923, 62925..62942, 62944..63042,
		63044..63050, 63052..63066, 63068..63114, 63116..63118, 63120..63134, 63136..63154, 63156..63169,
		63171..63173, 63175..63177, 63179, 63184..63189, 63191..63195, 63197, 63199..63217, 63219..63227,
		63230..63244, 63246, 63248..63253, 63255..63291, 63293..63374, 63376..63386, 63388..63410,
		63412..63429, 63431, 63432, 63434, 63437, 63439..63449, 63451..63473, 63475..63484, 63486..63666,
		63668..63682, 63684..63703, 63705, 63707..63720, 63722..63727, 63729, 63731..63874, 63876..63894,
		63896..63902, 63904..63906, 63908..63926, 63928..63950, 63952..63957, 63959..63963, 63965..63989,
		63991..63995, 63997..64074, 64076..64078, 64080..64098, 64100..64118, 64120..64142, 64144..64154,
		64156..64178, 64180..64205, 64208..64217, 64219..64229, 64231..64235, 64237..64241, 64243..64245,
		64247..64251, 64254..64264, 64266, 64268..64279, 64281, 64283..64296, 64298..64303, 64305..64308,
		64310, 64313..64316, 64318..64394, 64396..64438, 64440..64457, 64459..64474, 64476..64498,
		64500, 64501, 64503, 64504, 64506, 64507, 64509..64642, 64644..64646, 64648..64662, 64664..64674,
		64676..64678, 64680..64690, 64692..64694, 64696..64705, 64708, 64709, 64712..64715, 64717,
		64718, 64720..64725, 64733..64735, 64737, 64739, 64746..64751, 64760..64763, 64765..64898,
		64900..64914, 64916..64930, 64932..64946, 64948..64961, 64963..64977, 64979..64993, 64995..65009,
		65011..65102, 65104..65118, 65120..65126, 65128..65142, 65144..65166, 65168..65182, 65184..65229,
		65232..65245, 65248..65253, 65255..65259, 65262..65269, 65271..65275, 65278..65287, 65294,
		65296..65303, 65309..65317, 65319, 65322..65324, 65326, 65327, 65330, 65332, 65338, 65339,
		65342..65418, 65420..65422, 65424..65434, 65436..65458, 65460..65462, 65464..65481, 65484,
		65485, 65488..65497, 65500..65502, 65504..65509, 65511, 65512, 65514, 65515, 65517..65521,
		65524, 65525, 65528, 65530, 65531, 65534..65535
);}

