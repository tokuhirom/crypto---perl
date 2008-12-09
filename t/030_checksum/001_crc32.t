use strict;
use warnings;
use Test::More tests => 2;
use Crypt::Cryptopp;

{
    my $crc = Crypt::Cryptopp::CRC32->new();
    isa_ok $crc, 'Crypt::Cryptopp::CRC32';
    $crc->update("HOGE");
    is unpack("H*", $crc->final()), 'ee09acbd';
}

