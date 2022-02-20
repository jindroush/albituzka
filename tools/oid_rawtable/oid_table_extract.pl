#extractor of raw->internal OIDs from OidProducer.exe
#works with file with MD5 78af7c4610995f7b98f35e3261e3dd19
#for other file versions/MD5, seek constant must be most probably changed
use constant TBL => 0x8F9DE0;

use strict;

open IN, "OidProducer10.20.exe" or die;
binmode IN;

sysseek( IN, TBL, 0 );
my $buf;
sysread( IN, $buf, 65536 * 4 );
close IN;

my @dw = unpack( "V*", $buf );
if( scalar @dw != 0x10000 )
{
	die "reading of table failed";
}


my $first;
my @o;

for(my $i = 0; $i < 65536; $i++ )
{
	if( ! defined $first )
	{
		$first = $dw[$i];
		next;
	}

	my $prev = $dw[$i-1];
	if( $prev + 1 == $dw[$i] )
	{
		next;
	}
	else
	{
		if( $first == $prev )
		{
			push @o, $first;
		}
		elsif( $first+1 == $prev )
		{
			push @o, $first;
			push @o, $prev;
		}
		else
		{
			push @o, $first . ".." . $prev;
		}
		$first = $dw[$i];
	}
}
if( $first )
{
	my $last = $dw[65535];
	push @o, $first . ".." . $last;
}


open OUT, ">perl_code.txt" or die;

print OUT "sub oid_converter_init()\n";
print OUT "{\n";
print OUT "\t#index to the array is RAW, printed code. Value in the array is INTERNAL pen code (index to OID table)\n";
print OUT "\t\@oid_tbl_raw2int = (\n";

my $line;
foreach my $o ( @o )
{
	if( ! $line )
	{
		$line = "\t\t" . $o;
	}
	else
	{
		$line .= ", " . $o;
	}

	if( length( $line ) > 90 )
	{
		print OUT $line, ",\n";
		$line = undef;
	}
}

print OUT $line , "\n" if( $line );
print OUT ");}\n\n";
