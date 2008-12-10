use strict;
use warnings;
use Test::Base;
use Crypt::Cryptopp;

plan tests => 1*blocks;

filters {
    input => [qw/hash/],
};

sub hash {
    my $type = shift;
    my $hash = Crypt::Cryptopp::HashTransformation->new($type);
    $hash->update('HOGE');
    unpack("H*", $hash->final());
}

run_is input => 'expected';

__END__

===
--- input: MD2
--- expected: ee2a4aaed72a00adf39028f2930ab171

===
--- input: MD4
--- expected: 56b8c88b06beef382192eaa7b1abefaa

===
--- input: MD5
--- expected: ec40dbe9bf8521328f3c8e6d4c8b981c

===
--- input: SHA1
--- expected: 96e07bbd5540a76117ab213480ac2be9f88a85cc

===
--- SKIP
--- input: SHA224
--- expected: 46851275d83669d2b3eb2fd6163e2dc00de8f61a05217a22c2d9a1a4

===
--- input: SHA256
--- expected: 97fdb6bba1e280b8357a5237ccf2e6fa8302d1736a4282ac57a41e096f76e283

===
--- input: SHA384
--- expected: a12751712ad39e05d20fa2d775ec8827625fa69cd2463985f6e44db23e8131d4973ba0aad1428602a716c4fe368dede4

===
--- input: SHA512
--- expected: 85893827bd3261d794460640381c5949b21cdc7758ef02189ff1a80239af9386537e5066f63bd9f797a0f07177b003b542a9eb95d92d38207315d312255a60f4

===
--- input: Whirlpool
--- expected: 694a0f7233b8d4a49fef4595f609b9525719c47f6ec23b20f2bbf4d08b444082913819111b7112e0cf1326d451c3f685b00fbdce5f93ca01b6322cb004c78556

===
--- input: Tiger
--- expected: 3352337675d0b2e1690b113dd68aa6ce74365741c7163442

===
--- input: CRC32
--- expected: ee09acbd

===
--- input: Adler32
--- expected: 02e40124

===
--- input: RIPEMD160
--- expected: cf4da8546417e7af5c53ea84cbdd4c496723b35a

===
--- input: RIPEMD320
--- expected: dc6613e90b0323daed14bb04094c7dc6cbd64d7f3d9fd6d6950930e4a9c55ae37c1635110b6c814f

===
--- input: RIPEMD128
--- expected: 3699da6829e23fff9030f37a35e311fa

===
--- input: RIPEMD256
--- expected: 5bb2048242e389629885e3d2059c447241cf75901535c35115843ff3a4d3ca73

