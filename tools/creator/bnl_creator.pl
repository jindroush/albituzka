# albi BNL creator tool
# part of https://github.com/jindroush/albituzka
# this tool consumes bnl.json file as produced by bnl_dis.pl tool and creates bnl output file

# 11.01.2022 jindroush	first so so version (no cross-checks/data validation yet)
# 14.02.2022 jindroush	changed most numbers back to hex, as this makes all comparisons easier
# 15.02.2022 jindroush	rewrote quiz to have reasonable json varnames

#todo 
#cross checks
#data validation
#encryption - if not in json, have an option to choose between no-encrypt and full-encrypt
#creation report
#cmdline filename selection (also have data in json)
#check out if YAML is an option for perl

use strict;
use JSON;

my $in = "bnl.json";
open IN, $in or die;
my $json_a;
sysread( IN, $json_a, -s $in );
close IN;

my $hr_bnl = decode_json( $json_a );
die unless $hr_bnl;

#print join( "-", sort keys %$hr_bln ), "\n";

my $block_header = "\xFF" x 0x200;
my $block_oids;
my $block_others;
my $block_media;

my $header_key = hex( $$hr_bnl{header_key} );
#die unless $header_key;
substr( $block_header, 0, 4 ) = pack( "V", $header_key );
substr( $block_header, 4, 4 ) = pack( "V", 0x200 ^ $header_key );

substr( $block_header, 0x5C, 4 ) = pack( "V", hex( $$hr_bnl{ book_id } ) );
substr( $block_header, 0x140, 4 ) = pack( "V", hex( $$hr_bnl{ prekey_dw } ) );
substr( $block_header, 0x144, 16 ) = pack( "C*", map( hex($_), @{$$hr_bnl{ prekey }} ) );

my @key = &keygen( [map( hex($_), @{$$hr_bnl{ prekey }} ) ], ( $header_key >> 24 ) & 0xFF );

my $hr_oids = $$hr_bnl{ oids };
my $max_oid = hex(( sort keys %$hr_oids )[-1] );

substr( $block_header, 0x18, 4 ) = pack( "vv", ( 0, $max_oid ) );

my $max_mode = -1;

my %ALL_MEDIAS;
for( my $i = 0; $i <= $max_oid; $i++ )
{
	my $k = sprintf( "0x%04X", $i );
	if( exists $$hr_oids{ $k } )
	{
		&parse_mediatable( $$hr_oids{ $k } );
	}
}

&parse_mediatable( $$hr_bnl{ "start_button_1st_read" } );
&parse_mediatable( $$hr_bnl{ "start_button_2nd_read" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr5" } );
&parse_mediatable( $$hr_bnl{ "book_mode_read" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_18" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_19" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_1a" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_1b" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_1c" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_1d" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_1e" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_1f" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_20" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_21" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_22" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_23" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_24" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_25" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_26" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_33" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_34" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_35" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_36" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_37" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_38" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_39" } );
&parse_mediatable( $$hr_bnl{ "unk_tbl_ptr_40" } );

die "Max book mode left uninitialized after parsing. Input json file is incorrect." if( $max_mode == -1 );
$max_mode++;
substr( $block_header, 0x2C, 4 ) = pack( "V", $max_mode );

############ numbering medias
my $media_cnt = 0;
foreach my $fn ( sort keys %ALL_MEDIAS )
{
	$ALL_MEDIAS{ $fn }{ idx } = $media_cnt++;
}
substr( $block_header, 0x1C, 4 ) = pack( "vv", $media_cnt, 0 );

$block_oids = "\xFF" x ( 4 * $max_oid + 4 );
my $ptr_others = length( $block_header ) + length( $block_oids );


############ writing mediatables
&write_mediatable_hdr( 0x03 * 4, $$hr_bnl{ "start_button_1st_read" } );
&write_mediatable_hdr( 0x04 * 4, $$hr_bnl{ "start_button_2nd_read" } );
&write_mediatable_hdr( 0x05 * 4, $$hr_bnl{ "unk_tbl_ptr5" } );
&write_mediatable_hdr( 0x09 * 4, $$hr_bnl{ "book_mode_read" } );
&write_mediatable_hdr( 0x18 * 4, $$hr_bnl{ "unk_tbl_ptr_18" } );
&write_mediatable_hdr( 0x19 * 4, $$hr_bnl{ "unk_tbl_ptr_19" } );
&write_mediatable_hdr( 0x1a * 4, $$hr_bnl{ "unk_tbl_ptr_1a" } );
&write_mediatable_hdr( 0x1b * 4, $$hr_bnl{ "unk_tbl_ptr_1b" } );
&write_mediatable_hdr( 0x1c * 4, $$hr_bnl{ "unk_tbl_ptr_1c" } );
&write_mediatable_hdr( 0x1d * 4, $$hr_bnl{ "unk_tbl_ptr_1d" } );
&write_mediatable_hdr( 0x1e * 4, $$hr_bnl{ "unk_tbl_ptr_1e" } );
&write_mediatable_hdr( 0x1f * 4, $$hr_bnl{ "unk_tbl_ptr_1f" } );
&write_mediatable_hdr( 0x20 * 4, $$hr_bnl{ "unk_tbl_ptr_20" } );
&write_mediatable_hdr( 0x21 * 4, $$hr_bnl{ "unk_tbl_ptr_21" } );
&write_mediatable_hdr( 0x22 * 4, $$hr_bnl{ "unk_tbl_ptr_22" } );
&write_mediatable_hdr( 0x23 * 4, $$hr_bnl{ "unk_tbl_ptr_23" } );
&write_mediatable_hdr( 0x24 * 4, $$hr_bnl{ "unk_tbl_ptr_24" } );
&write_mediatable_hdr( 0x25 * 4, $$hr_bnl{ "unk_tbl_ptr_25" } );
&write_mediatable_hdr( 0x26 * 4, $$hr_bnl{ "unk_tbl_ptr_26" } );
&write_mediatable_hdr( 0x33 * 4, $$hr_bnl{ "unk_tbl_ptr_33" } );
&write_mediatable_hdr( 0x34 * 4, $$hr_bnl{ "unk_tbl_ptr_34" } );
&write_mediatable_hdr( 0x35 * 4, $$hr_bnl{ "unk_tbl_ptr_35" } );
&write_mediatable_hdr( 0x36 * 4, $$hr_bnl{ "unk_tbl_ptr_36" } );
&write_mediatable_hdr( 0x37 * 4, $$hr_bnl{ "unk_tbl_ptr_37" } );
&write_mediatable_hdr( 0x38 * 4, $$hr_bnl{ "unk_tbl_ptr_38" } );
&write_mediatable_hdr( 0x39 * 4, $$hr_bnl{ "unk_tbl_ptr_39" } );
&write_mediatable_hdr( 0x40 * 4, $$hr_bnl{ "unk_tbl_ptr_40" } );

########### and oid table (thus mediatables)
for( my $i = 0; $i <= $max_oid; $i++ )
{
	my $k = sprintf( "0x%04X", $i );
	if( exists $$hr_oids{ $k } )
	{
		my $ptr = &write_mediatable( $$hr_oids{ $k } );
		if( $ptr != 0xFFFFFFFF )
		{
			substr( $block_oids, $i * 4, 4 ) = pack( "V", $ptr );
		}
	}
}

&write_quiz( $$hr_bnl{ quiz} );

############ write oidtables
&write_oidtable_hdr( 0x12 * 4, $$hr_bnl{ "quiz_pos1" });
&write_oidtable_hdr( 0x13 * 4, $$hr_bnl{ "quiz_pos2" });
&write_oidtable_hdr( 0x14 * 4, $$hr_bnl{ "quiz_neg1" });
&write_oidtable_hdr( 0x15 * 4, $$hr_bnl{ "quiz_neg2" });
&write_oidtable_hdr( 0x16 * 4, $$hr_bnl{ "unk_tbl_ptr_16" });
&write_oidtable_hdr( 0x27 * 4, $$hr_bnl{ "unk_tbl_ptr_27" });
&write_oidtable_hdr( 0x28 * 4, $$hr_bnl{ "unk_tbl_ptr_28" });
&write_oidtable_hdr( 0x29 * 4, $$hr_bnl{ "unk_tbl_ptr_29" });
&write_oidtable_hdr( 0x2a * 4, $$hr_bnl{ "quiz_results" });


my $media_table_beg;
&write_media_table();
&write_all_media();

open OUT, ">bnl.bnl" or die;
binmode OUT;
print OUT $block_header;
print OUT $block_oids;
print OUT $block_others;
print OUT $block_media;
close OUT;

sub parse_mediatable()
{
	my $ar = $_[0];
	return unless $ar;

	foreach my $arr ( @$ar )
	{
		$max_mode = $$arr[0] if( $max_mode < $$arr[0] );
		foreach ( @{ $$arr[1] } )
		{
			$ALL_MEDIAS{ $_ }{ idx } = 0;
		}
	}
}

sub write_mediatable_hdr()
{
	my $hdr_ptr = $_[0];
	my $ar = $_[1];

	my $ptr = &write_mediatable( $ar );

	if( $ptr != 0xFFFFFFFF )
	{
		substr( $block_header, $hdr_ptr, 4 ) = pack( "V", $ptr ^ $header_key );
	}
}

sub write_mediatable()
{
	my $ar = $_[0];
	return 0xFFFFFFFF unless $ar;

	my $ptr_return = $ptr_others + length( $block_others );

	my $blk;
	for( my $mode = 0; $mode < $max_mode; $mode++ )
	{
		my $sub = pack( "v", 0 );
		foreach my $arr ( @$ar )
		{
			if( $$arr[0] == $mode )
			{
				$sub = pack( "v", scalar @{ $$arr[1] } );
				$sub .= pack( "v*", map( $ALL_MEDIAS{$_}{idx}, @{ $$arr[1] } ) );
				last;
			}
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

	my $ptr = &write_oidtable( $ar );

	if( $ptr != 0xFFFFFFFF )
	{
		substr( $block_header, $hdr_ptr, 4 ) = pack( "V", $ptr ^ $header_key );
	}
}

sub write_oidtable()
{
	my $ar = $_[0];
	return 0xFFFFFFFF unless $ar;

	my $ptr_return = $ptr_others + length( $block_others );

	my $blk = pack( "v", scalar @$ar );
	$blk .= pack( "v*", map( hex($_), @$ar ) );

	$block_others .= $blk;

	return $ptr_return;
}

sub pack_hex_oid_array()
{
	my $ar = $_[0];
	my $blk = pack( "v", scalar @$ar );
	$blk .= pack( "v*", map( hex($_), @$ar ) );
	return $blk;
}

sub write_quiz()
{
	my $ar = $_[0];
	my $ptr_return = $ptr_others + length( $block_others );
	substr( $block_header, 0x11 * 4, 4 ) = pack( "V", $ptr_return ^ $header_key );

	my $ptr_quiz = length( $block_others );

	my $quiz_cnt = scalar @$ar;
	my @quiz_ptrs = ( 0xFFFFFFFF ) x $quiz_cnt;
	$block_others .= pack( "V*", @quiz_ptrs );

	my $cnt_quiz = 0;
	foreach my $hr_quiz ( @$ar )
	{
		$quiz_ptrs[$cnt_quiz] = $ptr_others + length( $block_others );
		my $ar_questions = $$hr_quiz{ questions };
		my $quiz_type = hex($$hr_quiz{q_type} );

		my $qhdr = pack( "vvvvv", $quiz_type, scalar( @$ar_questions ), hex($$hr_quiz{q_asked}), hex($$hr_quiz{q_unk}), hex($$hr_quiz{q_oid}) );
		$block_others .= $qhdr;

		my $block_questions;
		my @questions_beg;		
		foreach my $hr_question ( @$ar_questions )
		{
			push @questions_beg, length( $block_questions );

			if( $quiz_type == 4 )
			{
        			my $question = pack( "vvvv", hex($$hr_question{q4_oid}), hex($$hr_question{q4_unk1}),hex($$hr_question{q4_unk2}),hex($$hr_question{q4_unk3}) );
				$question .= &pack_hex_oid_array( $$hr_question{q4_good_reply_oids} );
				$question .= &pack_hex_oid_array( $$hr_question{q4_unknown_oids} );
				$question .= &pack_hex_oid_array( $$hr_question{q4_good_reply_snd1} );
				$question .= &pack_hex_oid_array( $$hr_question{q4_good_reply_snd2} );
				$question .= &pack_hex_oid_array( $$hr_question{q4_bad_reply_snd1} );
				$question .= &pack_hex_oid_array( $$hr_question{q4_bad_reply_snd2} );
				$question .= &pack_hex_oid_array( $$hr_question{q4_final_good} );
				$question .= &pack_hex_oid_array( $$hr_question{q4_final_bad} );
				$block_questions .= $question;
			}
			else
			{
        			my $question = pack( "vv", hex($$hr_question{q1_unk}),hex($$hr_question{q1_oid}));
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
	my @blk = ( 0xFFFFFFFF ) x ($media_cnt+1);
	my $blk = pack( "V*", @blk );
	$block_others .= $blk;
}

sub write_all_media()
{
	my @arr;
	foreach my $fn ( keys %ALL_MEDIAS )
	{
		$arr[$ALL_MEDIAS{$fn}{idx}] = $fn;
	}

	my @ptrs;

	#hardcoded 0x200 value here - it's the file start padding value, and as such, it depends probably on
	#mp3 library limitations
	foreach my $fn ( @arr )
	{
		my $before_me = $ptr_others + length( $block_others ) + length( $block_media );

		my $rem = $before_me % 0x200;

		my $blk;
		if( $rem )
		{
			$blk = "\x00" x ( 0x200 - $rem );
			$before_me += 0x200 - $rem;
		}

		local *IN;
		open IN, $fn or "JSON file references sound file '$fn' which is not there/can't be opened";
		binmode IN;
		my $l = -s $fn;
		my $buf;
		sysread( IN, $buf, $l );
		close IN;

		&decrypt_mem( \$buf, \@key );
		$block_media .= $blk . $buf;
		push @ptrs, $before_me;
	}
	die "Assertion failed (number of pointers doesn't match number of media files)" if( scalar @ptrs != $media_cnt );
	push @ptrs, $ptr_others + length( $block_others ) + length( $block_media );
	substr( $block_others, $media_table_beg, 4*scalar(@ptrs) ) = pack( "V*", @ptrs );
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

	for( my $pk_ptr = 0; $pk_ptr < scalar( @$ar_pre_key ); $pk_ptr++ )
	{
		for( my $block = 0; $block < 8; $block++ )
		{
			$key[ $block * 16 * 4 + $pk_ptr * 4 + $keygen_tbl[$pk_ptr][$block] ] = ( $$ar_pre_key[ $pk_ptr ] + $pk ) & 0xFF;
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
