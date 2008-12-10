use strict;
use warnings;
use Test::Base;
use Crypt::Cryptopp;

plan tests => 3*blocks;

filters {
    input => [qw/rng/],
};

sub rng {
    my $type = shift;
    Crypt::Cryptopp::RandomNumberGenerator->new($type);
}

run {
    my $block = shift;
    my $rng = $block->input;
    like sprintf('%02x', $rng->generate_byte()),   qr/^[a-h0-9]{2}$/;
    like sprintf('%08x', $rng->generate_word32()), qr/^[a-h0-9]{8}$/;
    like $rng->algorithm_name(), qr/^[A-Za-z0-9]+$/, $rng->algorithm_name();
};

__END__

===
--- input: BlockingRng

===
--- input: NonblockingRng

