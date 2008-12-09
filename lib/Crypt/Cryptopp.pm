package Crypt::Cryptopp;
use strict;
use warnings;
use 5.008_001;
our $VERSION = '0.01';
use XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

{
    no strict 'refs';
    for my $klass (qw/SHA1 Tiger CRC32 Adler32/) {
        unshift @{"Crypt::Cryptopp::${klass}::ISA"}, 'Crypt::Cryptopp::HashTransformation';
    }
}

1;
__END__

=head1 NAME

Crypt::Cryptopp - crypto++ bindings for perl

=head1 SYNOPSIS

