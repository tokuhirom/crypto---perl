use strict;
use warnings;
use Test::More tests => 1;
use Crypt::Cryptopp;

my $sha1 = Crypt::Cryptopp::SHA1->new();
isa_ok $sha1, 'Crypt::Cryptopp::SHA1';

