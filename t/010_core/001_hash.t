use strict;
use warnings;
use Test::Base;
use Crypt::Cryptopp;

plan tests => 1*blocks;

filters {
    input => [qw/hash/],
};

sub hash {
    my $moniker = shift;
    my $klass = "Crypt::Cryptopp::$moniker";
    my $hash = $klass->new();
    $hash->update('HOGE');
    unpack("H*", $hash->final());
}

run_is input => 'expected';

__END__

===
--- input: MD2
--- expected: ee2a4aaed72a00adf39028f2930ab171

===
--- input: MD5
--- expected: ec40dbe9bf8521328f3c8e6d4c8b981c

===
--- input: SHA1
--- expected: 96e07bbd5540a76117ab213480ac2be9f88a85cc

===
--- input: Tiger
--- expected: 3352337675d0b2e1690b113dd68aa6ce74365741c7163442

===
--- input: CRC32
--- expected: ee09acbd

===
--- input: Adler32
--- expected: 02e40124

