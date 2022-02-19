#extractor of raw->internal OIDs from OidProducer
#works with file with MD5 78af7c4610995f7b98f35e3261e3dd19
#for other files, seek constant must be changed
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

open OUT, ">perl_code.txt" or die;

print OUT "sub oid_converter_init()\n";
print OUT "{\n";
print OUT "\t\@oid_tbl_raw2int = (\n";

for(my $i = 0; $i < 65536; $i++ )
{
	#printf( "%04X => %04X\n", $i, $dw[$i] );
	printf OUT "\t\t%d,\n", $dw[$i];
}
print OUT ");}\n\n";
