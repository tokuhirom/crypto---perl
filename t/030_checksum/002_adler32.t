use strict;
use warnings;
use Test::More tests => 2;
use Crypt::Cryptopp;

{
    my $crc = Crypt::Cryptopp::Adler32->new();
    isa_ok $crc, 'Crypt::Cryptopp::Adler32';
    $crc->update("hoge");
    is unpack("H*", $crc->final()), '042401a4';
}

