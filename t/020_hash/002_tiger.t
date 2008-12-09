use strict;
use warnings;
use Test::More tests => 3;
use Crypt::Cryptopp;

{
    my $sha1 = Crypt::Cryptopp::Tiger->new();
    isa_ok $sha1, 'Crypt::Cryptopp::Tiger';
    is unpack("H*", $sha1->final()), '3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3';
}

{
    my $sha1 = Crypt::Cryptopp::Tiger->new();
    $sha1->update('tee');
    is unpack("H*", $sha1->final()), 'ad3b7f45db7939e7c82a91502af9c30cc407753e2772516d';
}

