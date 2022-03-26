# albi BNL creator tool
# written by jindroush, published under MPL license
# part of https://github.com/jindroush/albituzka
# this tool consumes bnl.yaml file as produced by bnl_dis.pl tool and creates bnl output file
# parameters:
#	-input FNAME - changes input filename (default: bnl.yaml)
#	-output FNAME - change output filename (default: bnl.bnl)

# 11.01.2022 jindroush	first so so version (no cross-checks/data validation yet)
# 14.02.2022 jindroush	changed most numbers back to hex, as this makes all comparisons easier
# 15.02.2022 jindroush	rewrote quiz to have reasonable json varnames
# 18.03.2022 jindroush	switched to YAML format, added possibility of generating encryption vars on the fly
#				also added few error/cross/warning checks
# 19.03.2022 jindroush	added additional oid code formats oid_dec,oid_xHHHH,oid_dec_name,oid_xHHHH_name
#				additional checks of duplicate oids
#				generates file generate_oids.yaml -> input to oid_png_generator.pl @generate_oids.yaml [switches]
# 23.03.2022 jindroush	added additional checks for presence of mp3 files / unused mp3 files


#todo 
#creation report

use strict;
use YAML;
use File::Spec::Functions qw( splitpath catfile );

#globals for user
my $input_fn = "bnl.yaml";
my $output_fn = "bnl.bnl";
my $media_dir = ".";
my $encryption = 1;

#globals general
my %BNL;
my $block_header = "\xFF" x 0x200;
my $block_oids;
my $block_others;
my $block_media;

my %ALL_MEDIA;
my $book_id;

my $max_book_mode;
my $media_cnt;
my $header_key;
my @prekey;
my @real_key;
my $prekey_dw;

while( @ARGV )
{
	my $sw = shift @ARGV;
	if( $sw =~ /^(\-|\-\-|\/)(.+)$/ )
	{
		$sw = lc $sw;

		if( $sw eq 'input' )
		{
			$input_fn = shift @ARGV;
		}
		elsif( $sw eq 'output' )
		{
			$output_fn = shift @ARGV;
		}
	}
	else
	{
		die;
	}
}

&load_input();
my $hr_bnl = \%BNL;

#fill up the header with emptiness
$block_header = "\xFF" x 0x200;

#first setup encryption
if( exists $$hr_bnl{header}{encryption} )
{
	print "Encryption: from input file\n";
	$header_key = hex( $$hr_bnl{header}{encryption}{header_key} );
	$prekey_dw = hex( $$hr_bnl{header}{encryption}{ prekey_dw } );
	@prekey = map( hex($_), @{$$hr_bnl{header}{encryption}{ prekey }} );
}
else
{
	#TODO this was never actually tested by me
	#first part - there is uncertainty if prekey_dw could be fully randomized
	#second part - depends on correct header key -> quizes don't work if it's incorrect
	if( $encryption == 1 )
	{
		print "Encryption: generated strong\n";
		$header_key = unpack( "V", pack( "C4", &gen_rand_arr( 4 ) ) );
		$prekey_dw = unpack( "V", pack( "C4", &gen_rand_arr( 4 ) ) );
		$prekey_dw = ( $prekey_dw & 0xFFFFFF00 ) | (( 0xF5 - ( $header_key >> 24 ) ) & 0xFF );
		@prekey = &gen_rand_arr( 16 );
	}
	else
	{
		print "Encryption: generated weak\n";
		$header_key = 0x00000100;
		$prekey_dw = 0xF5;
		@prekey = ( 0 ) x 16;
	}
}
die "Incorrect encryption key length" if ( scalar( @prekey ) != 16 );
die "Incorrect encryption check" if( ((( $header_key >> 24 ) + ( $prekey_dw & 0xFF ) ) & 0xFF ) != 0xF5 );

#and add those values into header
substr( $block_header, 0, 4 ) = pack( "V", $header_key );
substr( $block_header, 4, 4 ) = pack( "V", 0x200 ^ $header_key );
substr( $block_header, 0x140, 4 ) = pack( "V", $prekey_dw );
substr( $block_header, 0x144, 16 ) = pack( "C*", @prekey );
@real_key = &keygen( \@prekey, ( $header_key >> 24 ) & 0xFF );

#first pass over OIDS to get min and max
my $hr_oids = $$hr_bnl{ oids };

#here we will also create the translation tables
my @OID_ARR;
my %oid_noprint;
my %oid_to_num;

#TODO min oid processing currently not present, always based at 0 (commercial files based at 0 anyway)
my $min_oid = 0;
my $max_oid = 0;
foreach my $txt_oid ( keys %$hr_oids )
{
	if( $txt_oid =~ /^oid_(x[A-F0-9a-f]{4}|\d+)(_(.+))*$/ )
	{
		my $num = $1;
		my $ext = $3;
		$num = hex( $num ) if( $num =~ /^x/ );

		if( $OID_ARR[$num] )
		{   
			die "Duplicate oid definition for '$txt_oid' (previous def $OID_ARR[$num])";
		}

		$OID_ARR[$num] = $txt_oid;
		$oid_to_num{ $txt_oid } = $num;
		$max_oid = $num if( $max_oid < $num );
	}
	else
	{
		die "Invalid oid format $txt_oid";
	}
}

printf( "Oids range: 0x%04X-0x%04X\n", $min_oid, $max_oid );
substr( $block_header, 0x18, 4 ) = pack( "vv", ( $min_oid, $max_oid ) );

#before parsing any arrays, set to known bad value
$max_book_mode = -1;

#preparse whole OID table
for( my $i = $min_oid; $i <= $max_oid; $i++ )
{
	my $k = $OID_ARR[ $i ];
	if( exists $$hr_oids{ $k } )
	{
		&parse_media_arrays( $$hr_oids{ $k } );
	}
}

#preparse all other media-only tables
#this array should be always in sync with data in bnl_dis
#first column is dword offset in header, second column name in input file
my @oid_tables = (
	[ 0x03, "start_button_1st_read" ],
	[ 0x04, "start_button_2nd_read" ],
	[ 0x05, "unk_tbl_ptr5" ],
	[ 0x09, "book_mode_read" ],
	[ 0x18, "unk_tbl_ptr_18" ],
	[ 0x19, "unk_tbl_ptr_19" ],
	[ 0x1a, "unk_tbl_ptr_1a" ],
	[ 0x1b, "unk_tbl_ptr_1b" ],
	[ 0x1c, "unk_tbl_ptr_1c" ],
	[ 0x1d, "unk_tbl_ptr_1d" ],
	[ 0x1e, "unk_tbl_ptr_1e" ],
	[ 0x1f, "unk_tbl_ptr_1f" ],
	[ 0x20, "unk_tbl_ptr_20" ],
	[ 0x21, "unk_tbl_ptr_21" ],
	[ 0x22, "unk_tbl_ptr_22" ],
	[ 0x23, "unk_tbl_ptr_23" ],
	[ 0x24, "unk_tbl_ptr_24" ],
	[ 0x25, "unk_tbl_ptr_25" ],
	[ 0x26, "unk_tbl_ptr_26" ],
	[ 0x33, "unk_tbl_ptr_33" ],
	[ 0x34, "unk_tbl_ptr_34" ],
	[ 0x35, "unk_tbl_ptr_35" ],
	[ 0x36, "unk_tbl_ptr_36" ],
	[ 0x37, "unk_tbl_ptr_37" ],
	[ 0x38, "unk_tbl_ptr_38" ],
	[ 0x39, "unk_tbl_ptr_39" ],
	[ 0x40, "unk_tbl_ptr_40" ]
);             

foreach ( @oid_tables )
{
	&parse_media_arrays( $$hr_bnl{ header }{ $$_[1] } );
}
#in this moment, we should have parsed all oid-mode-media tables, so we know the max_book_mode
die "Max book mode left uninitialized after parsing. Input json file is incorrect." if( $max_book_mode == -1 );
#actually, there is a question if algorithms of guessing max_book_mode and min_oid/max_oid and possibly also media_cnt
#should be done this way
#there are two ways:
#1) store the values hardcoded into YAML input, and warn/die if the bounds are not met
#2) guess the values as maxima/minima from the actual data
#I chose 2) which is slightly more complicated and doesn't always produce exact replica of disassembled input
$max_book_mode++;
substr( $block_header, 0x2C, 4 ) = pack( "V", $max_book_mode );
print "Book modes: $max_book_mode\n";

#and write book_id into header
$book_id = hex($$hr_bnl{header}{book_id} );
if( $book_id >= 701 && $book_id <= 9999 )
{
	substr( $block_header, 0x5C, 4 ) = pack( "V", $book_id );
	printf( "Book id: 0x%04X (%d)\n", $book_id, $book_id );
}
else
{
	die "Book id $book_id is out of range (701-9999)";
}

#numbering media files, alphasorted
$media_cnt = 0;
foreach my $fn ( sort keys %ALL_MEDIA )
{
	$ALL_MEDIA{ $fn }{ idx } = $media_cnt++;
}
substr( $block_header, 0x1C, 4 ) = pack( "vv", $media_cnt, 0 );
printf "Media: references %d files\n", $media_cnt;

#this creates empty oid array
$block_oids = "\xFF" x ( ( $max_oid - $min_oid + 1 ) * 4 );

my $ptr_others = length( $block_header ) + length( $block_oids );


#writing all media_arrays referenced from header
foreach ( @oid_tables )
{
	&write_media_arrays_hdr( $$_[0] * 4, $$hr_bnl{ header }{ $$_[1] } );
}

# write all media_arrays associated with an OID and patch oid array (also mediatables)
for( my $i = $min_oid; $i <= $max_oid; $i++ )
{
	my $k = $OID_ARR[ $i ];
	if( exists $$hr_oids{ $k } )
	{
		my $ptr = &write_media_array( $$hr_oids{ $k } );
		if( $ptr != 0xFFFFFFFF )
		{
			substr( $block_oids, $i * 4, 4 ) = pack( "V", $ptr );
		}
	}
}

#write the quizes
&write_quiz( $$hr_bnl{ quiz }{ quizes } );

#write oidtables
&write_oidtable_hdr( 0x12 * 4, $$hr_bnl{ quiz }{ "quiz_pos1" });
&write_oidtable_hdr( 0x13 * 4, $$hr_bnl{ quiz }{ "quiz_pos2" });
&write_oidtable_hdr( 0x14 * 4, $$hr_bnl{ quiz }{ "quiz_neg1" });
&write_oidtable_hdr( 0x15 * 4, $$hr_bnl{ quiz }{ "quiz_neg2" });
&write_oidtable_hdr( 0x16 * 4, $$hr_bnl{ header }{ "unk_tbl_ptr_16" });
&write_oidtable_hdr( 0x27 * 4, $$hr_bnl{ header }{ "unk_tbl_ptr_27" });
&write_oidtable_hdr( 0x28 * 4, $$hr_bnl{ header }{ "unk_tbl_ptr_28" });
&write_oidtable_hdr( 0x29 * 4, $$hr_bnl{ header }{ "unk_tbl_ptr_29" });
&write_oidtable_hdr( 0x2a * 4, $$hr_bnl{ quiz }{ "quiz_results" });


my $media_table_beg;

#create media_table
&write_media_table();

#encrypt and write all media files
&write_all_media();

#and output everything to disk
open OUT, ">" . $output_fn or die "Can't write to '$output_fn'";
binmode OUT;
print OUT $block_header;
print OUT $block_oids;
print OUT $block_others;
print OUT $block_media;
close OUT;
printf "Created $output_fn, %d bytes long.\n", -s $output_fn;

#this creates helper YAML file which could be fed to oid_png_generator.pl
#it saves lots of work of generating pngs one by one
my @to_print;
#always generate start icon
&generate_print( \@to_print, $book_id, "icon_start" );

#values of know system icons
my %SYS_ICONS = (
	"volume_up" => 0x07,
	"volume_down" => 0x08,
	"stop" => 0x06,
	"compare" => 0x63
);

#generate oids for system icons
foreach my $icon ( @{ $$hr_bnl{ header }{ sys_icons } } )
{
	my $oid;

	if( exists $SYS_ICONS{ $icon } )
	{
		&generate_print( \@to_print, $SYS_ICONS{ $icon }, "icon_" . $icon );
	}
	else
	{
		die "Referencing unknow sys_icon '$icon'";
	}
}

#values of all 12 modes
my %MODE_ICONS = (
	"mode_1" => 0x04,
	"mode_2" => 0x05,
	"mode_3" => 0x03,
	"mode_4" => 0x02,
	"mode_5" => 0x01,
	"mode_6" => 0x0225,
	"mode_7" => 0x0226,
	"mode_8" => 0x0227,
	"mode_9" => 0x0228,
	"mode_10" => 0x0229,
	"mode_11" => 0x022A,
	"mode_12" => 0x022B
);

#generate oids for used modes
for( my $mode = 0; $mode < $max_book_mode; $mode++ )
{
	my $k = sprintf( "mode_%d", $mode );
	next if( ! exists $MODE_ICONS{ $k } );
	&generate_print( \@to_print, $MODE_ICONS{ $k }, "icon_" . $k );
}

#generate oids for all quizes
for( my $oid = 100; $oid <= 499; $oid++ )
{
	my $k = $OID_ARR[ $oid ];
	next if( ! $k );
	next if( $oid_noprint{ $oid } );
	&generate_print( \@to_print, $oid, "icon_quiz_" . ($oid -99) );
}

#and generate oids for all user defined oids
#always skip non-printed oids (this is a bit of guessing)
for( my $oid = 10000; $oid <= $max_oid; $oid++ )
{
	my $k = $OID_ARR[ $oid ];
	next if( ! $k );
	next if( $oid_noprint{ $oid } );
	my $kk = $k;
	$kk =~ s/^oid_//;
	&generate_print( \@to_print, $oid, $kk );
}

#and print them to file
if( @to_print )
{
	open OUT, ">" . "generate_oids.yaml" or die;
	print OUT YAML::Dump(\@to_print);
	close OUT;
}

print "Done.\n";

sub generate_print()
{
	my $ar = $_[0];

	my %ONE_OID;
	$ONE_OID{ oid } = $_[1];
	$ONE_OID{ fname } = "oid_" . $_[2] . ".png";
	push @$ar, \%ONE_OID;
}

sub parse_media_arrays()
{
	my $hr = $_[0];
	return unless $hr;
	die "Expected hash reference, invalid input file!" if( ref $hr ne "HASH" );

	foreach my $modea ( sort keys %$hr )
	{
		my $mode;
		if( $modea =~ /^mode_(\d+)$/ )
		{
			$mode = $1;
		}
		else
		{
			die "Expected keyword mode_X, got '$modea', invalid input file";
		}

		#here we're getting highest possible book_mode
		$max_book_mode = $mode if( $max_book_mode < $mode );
		foreach ( @{ $$hr{$modea} } )
		{
			$ALL_MEDIA{ $_ }{ idx } = 0;
		}
	}
}

#convert oid_XXXX to dec number
sub oid_to_num()
{
	my $inp = $_[0];

	return $oid_to_num{ $inp } if( exists $oid_to_num{ $inp } );

	if( $inp =~ /^oid_(x[A-F0-9a-f]{4}|\d+)(_(.+))*$/ )
	{
		my $num = $1;
		$num = hex( $num ) if( $num =~ /^x/ );
		return $num;
	}
	die "Invalid oid format '$inp'";
}

#write mediatable and patch encrypted pointer to header
sub write_media_arrays_hdr()
{
	my $hdr_ptr = $_[0];
	my $ar = $_[1];

	my $ptr = &write_media_array( $ar );

	if( $ptr != 0xFFFFFFFF )
	{
		substr( $block_header, $hdr_ptr, 4 ) = pack( "V", $ptr ^ $header_key );
	}
}

#write the media_array itself
#depends on numbered ALL_MEDIA array
sub write_media_array()
{
	my $hr = $_[0];
	return 0xFFFFFFFF unless $hr;

	my $ptr_return = $ptr_others + length( $block_others );

	my $blk;
	for( my $mode = 0; $mode < $max_book_mode; $mode++ )
	{
		my $key = sprintf( "mode_%d", $mode );

		my $sub;
		if( exists $$hr{ $key } )
		{
			my $ar = $$hr{ $key };
			$sub = pack( "v", scalar @$ar );
			$sub .= pack( "v*", map( $ALL_MEDIA{$_}{idx}, @$ar ) );
		}
		else
		{
			#if the mode is skipped, we just write \0 as 'empty' array
			$sub = pack( "v", 0 );
		}
		$blk .= $sub;
	}
	$block_others .= $blk;

	return $ptr_return;
}

sub write_oidtable_hdr()
{
	my $hdr_ptr = $_[0];
	my $ar = $_[1];

	my $ptr = &write_oidtable( $ar, 1 );

	if( $ptr != 0xFFFFFFFF )
	{
		substr( $block_header, $hdr_ptr, 4 ) = pack( "V", $ptr ^ $header_key );
	}
}

sub write_oidtable()
{
	my $ar = $_[0];
	my $noprint = $_[1];

	return 0xFFFFFFFF unless $ar;

	my $ptr_return = $ptr_others + length( $block_others );

	my $blk = pack( "v", scalar @$ar );
	$blk .= pack( "v*", map( &oid_to_num($_), @$ar ) );

	foreach ( @$ar )
	{
		&warn_on_oid( $_, "oidtable" );
		if( $noprint )
		{
			my $oid = &oid_to_num($_);
			$oid_noprint{ $oid } = 1;
		}
	}
	$block_others .= $blk;

	return $ptr_return;
}

sub warn_on_oid()
{
	my $oid = $_[0];
	my $str = $_[1];

	if( ! exists $$hr_bnl{oids}{$oid} )
	{
		print "warning: there is a reference to OID $oid (from $str) not present in oid table!\n";
	}
}

sub pack_hex_oid_array()
{
	my $ar = $_[0];
	my $noprint = $_[1];

	my $blk = pack( "v", scalar @$ar );
	$blk .= pack( "v*", map( &oid_to_num($_), @$ar ) );
	foreach ( @$ar )
	{
		&warn_on_oid( $_, "oid_array" );
		if( $noprint )
		{
			my $oid = &oid_to_num($_);
			$oid_noprint{ $oid } = 1;
		}
	}

	return $blk;
}

sub write_quiz()
{
	my $ar = $_[0];
	my $ptr_return = $ptr_others + length( $block_others );

	#write ptr to quiz pointers
	substr( $block_header, 0x11 * 4, 4 ) = pack( "V", $ptr_return ^ $header_key );

	#remember where we write empty quiz pointers table
	my $ptr_quiz = length( $block_others );
	my $quiz_cnt = scalar @$ar;
	print "warning: zero length of quiz tables!\n" if( ! $quiz_cnt );
	my @quiz_ptrs = ( 0xFFFFFFFF ) x $quiz_cnt;
	$block_others .= pack( "V*", @quiz_ptrs );

	my $cnt_quiz = 0;
	foreach my $hr_quiz ( @$ar )
	{
		$quiz_ptrs[$cnt_quiz] = $ptr_others + length( $block_others );
		my $ar_questions = $$hr_quiz{ questions };
		my $quiz_type = hex($$hr_quiz{q_type} );
		if( $quiz_type != 0 && $quiz_type != 4 )
		{
			printf "warning: quiz_type %d is not documented, could cause unknown behavior!\n", $quiz_type;
		}

		&warn_on_oid( $$hr_quiz{ q_oid }, "q_oid" );

		my $q = scalar( @$ar_questions );
		my $qa = hex( $$hr_quiz{ q_asked } );

		if( $q < $qa )
		{
			printf "warning: number of questions (%d) < questions asked (%d)!\n", $q, $qa;
		}

		if( $quiz_type == 0 )
		{
			my $qr = scalar( @{ $$hr_bnl{quiz}{quiz_results} } );
			if( $qa + 1 != $qr )
			{
				printf "warning: number of questions asked (%d) does not match number of results (%d) in quiz_results!\n", $qa, $qr;
			}
		}

		my $qhdr = pack( "vvvvv", $quiz_type, scalar( @$ar_questions ), hex($$hr_quiz{q_asked}), hex($$hr_quiz{q_unk}), &oid_to_num($$hr_quiz{q_oid}) );
		$block_others .= $qhdr;

		my $block_questions;
		my @questions_beg;		
		foreach my $hr_question ( @$ar_questions )
		{
			push @questions_beg, length( $block_questions );

			if( $quiz_type == 4 )
			{
				&warn_on_oid( $$hr_question{ q4_oid }, "q4_oid" );

        			my $question = pack( "vvvv", &oid_to_num($$hr_question{q4_oid}), hex($$hr_question{q4_unk1}),hex($$hr_question{q4_unk2}),hex($$hr_question{q4_unk3}) );
				$question .= &pack_hex_oid_array( $$hr_question{q4_good_reply_oids} );
				$question .= &pack_hex_oid_array( $$hr_question{q4_unknown_oids} );
				$question .= &pack_hex_oid_array( $$hr_question{q4_good_reply_snd1}, 1 );
				$question .= &pack_hex_oid_array( $$hr_question{q4_good_reply_snd2}, 1 );
				$question .= &pack_hex_oid_array( $$hr_question{q4_bad_reply_snd1}, 1 );
				$question .= &pack_hex_oid_array( $$hr_question{q4_bad_reply_snd2}, 1 );
				$question .= &pack_hex_oid_array( $$hr_question{q4_final_good}, 1 );
				$question .= &pack_hex_oid_array( $$hr_question{q4_final_bad}, 1 );
				$block_questions .= $question;
			}
			else
			{
				&warn_on_oid( $$hr_question{ q1_oid }, "q1_oid" );
				$oid_noprint{ &oid_to_num($$hr_question{q1_oid}) } = 1;

        			my $question = pack( "vv", hex($$hr_question{q1_unk}),&oid_to_num($$hr_question{q1_oid}));
				$question .= &pack_hex_oid_array( $$hr_question{q1_good_reply_oids} );
				$block_questions .= $question;
			}
		}
		my $ptr_questions = $ptr_others + length( $block_others ) + scalar( @questions_beg ) * 4;
		foreach my $q_ptr ( @questions_beg )
		{
			$q_ptr += $ptr_questions;
		}
		$block_others .= pack( "V*", @questions_beg );
		$block_others .= $block_questions;
		$cnt_quiz++;
	}		

	#rewrite quiz to point to correct places
	substr( $block_others, $ptr_quiz, 4* $quiz_cnt ) = pack( "V*", @quiz_ptrs );
}

sub write_media_table()
{
	my $ptr_return = $ptr_others + length( $block_others );
	substr( $block_header, 0x2 * 4, 4 ) = pack( "V", $ptr_return ^ $header_key );

	$media_table_beg = length( $block_others );
	my @blk = ( 0xFFFFFFFF ) x ( $media_cnt + 1 );
	my $blk = pack( "V*", @blk );
	$block_others .= $blk;
}

sub write_all_media()
{
	my @arr;
	foreach my $fn ( keys %ALL_MEDIA )
	{
		$arr[$ALL_MEDIA{$fn}{idx}] = $fn;
	}

	my @ptrs;

	my %FILES;
	local *DIR;
	opendir DIR, $media_dir or die;
	while( my $e = readdir DIR )
	{
		next if( $e eq '.' || $e eq '..' );
		next if( $e !~ /\.mp3$/i );

		my $f = catfile( $media_dir, $e );
		$FILES{ $f } = 0;		
	}
	closedir DIR;

	my $errors = 0;

	#hardcoded 0x200 value here - it's the file start padding value, and as such, it depends
	#on mp3 library limitations or, more probably, on fat-on-sdcart sectors
	foreach my $fn ( @arr )
	{
		my $before_me = $ptr_others + length( $block_others ) + length( $block_media );

		my $remains_to_be_padded = $before_me % 0x200;

		my $blk;
		if( $remains_to_be_padded )
		{
			$blk = "\x00" x ( 0x200 - $remains_to_be_padded );
			$before_me += 0x200 - $remains_to_be_padded;
		}

		local *IN;

		my $ffn = catfile( $media_dir, $fn );
		if( ! open IN, $ffn )
		{
			print "Input file references sound file '$ffn' which is not there/can't be opened\n";
			$errors++;
			next;
		}
		binmode IN;
		my $l = -s $ffn;
		my $buf;
		sysread( IN, $buf, $l );
		close IN;

		if( exists $FILES{ $ffn } )
		{
			$FILES{ $ffn } = 1;
		}
		else
		{
			print "warning: file '$ffn' referenced is not in media dir '$media_dir'\n";
		}

		&decrypt_mem( \$buf, \@real_key );
		$block_media .= $blk . $buf;
		push @ptrs, $before_me;
	}

	if( $errors )
	{
		die "There were errors loading mp3 files, stopping.";
	}

	die "Assertion failed (number of pointers doesn't match number of media files)" if( scalar @ptrs != $media_cnt );
	push @ptrs, $ptr_others + length( $block_others ) + length( $block_media );
	substr( $block_others, $media_table_beg, 4*scalar(@ptrs) ) = pack( "V*", @ptrs );

	#just for warning that there are some unused media files (may signal omission in YAML authoring)
	foreach my $f ( sort keys %FILES )
	{
		if( ! $FILES{ $f } )
		{
			print "warning: there is unreferenced file in media dir: '$f'\n";
		}
	} 
}

sub keygen()
{
	my $ar_pre_key = $_[0];
	my $pk = $_[1];

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

	#every byte of input key
	for( my $pk_ptr = 0; $pk_ptr < scalar( @$ar_pre_key ); $pk_ptr++ )
	{
		#is written on the same 0-3 offset in each of 8 block
		for( my $block = 0; $block < 8; $block++ )
		{
			#the position is modified by keygen_tbl
			$key[ $block * 16 * 4 + $pk_ptr * 4 + $keygen_tbl[$pk_ptr][$block] ] = ( $$ar_pre_key[ $pk_ptr ] + $pk ) & 0xFF;
		}
	}
	return @key;
}

#in fact, it does both encrypt and decrypt, because of XOR properties
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

sub gen_rand_arr()
{
	my $len = $_[0];
	my @o;
	while( $len-- )
	{
		push @o, int(rand(256));
	}
	return @o;
}

sub load_input()
{
	open IN, $input_fn or die "Can't open '$input_fn'";
	my $yaml_a;
	sysread( IN, $yaml_a, -s $input_fn );
	close IN;
	my $lines = () = $yaml_a =~ /\n/g;
	
	printf "Loaded %d lines from %s\n", $lines, $input_fn;

	( $BNL{header},$BNL{quiz},$BNL{oids} ) = YAML::Load( $yaml_a );
	my $bad = 0;
	$bad = 1 if( ref( $BNL{header} ) ne "HASH" );
	$bad = 1 if( ref( $BNL{quiz} ) ne "HASH" );
	$bad = 1 if( ref( $BNL{oids} ) ne "HASH" );

	die "Input file '$input_fn' is malformed, one of the three main sections is missing!\n" if( $bad );

	print "Parsed input data.\n";
}
