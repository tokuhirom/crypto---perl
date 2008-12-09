use strict;
use warnings;
use Test::More tests => 3;
use Crypt::Cryptopp;

{
    my $sha1 = Crypt::Cryptopp::SHA1->new();
    isa_ok $sha1, 'Crypt::Cryptopp::SHA1';
    is unpack("H*", $sha1->final()), 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
}

{
    my $sha1 = Crypt::Cryptopp::SHA1->new();
    $sha1->update('tee');
    is unpack("H*", $sha1->final()), '62a2f664b05813accb0db2cf73622bc342b662c4';
}

