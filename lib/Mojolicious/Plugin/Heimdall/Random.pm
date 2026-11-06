package Mojolicious::Plugin::Heimdall::Random;
use Mojo::Base -base, -signatures;

use Crypt::URandom::Token ();

my @UPPER   = ('A' .. 'Z');
my @LOWER   = ('a' .. 'z');
my @DIGITS  = ('0' .. '9');
my @SYMBOLS = split //, '!@#$%^&*()-_=+[]{};:,.<>?';

sub token ($self, $length = 44) {
  return Crypt::URandom::Token::urandom_token($length);
}

sub password ($self, $length = 16) {
  $length = 16 if $length < 4;
  my @alphabet = (@UPPER, @LOWER, @DIGITS, @SYMBOLS);
  return Crypt::URandom::Token::urandom_token($length, \@alphabet);
}

sub string ($self, $length = 32, $alphabet = undef) {
  return Crypt::URandom::Token::urandom_token($length, $alphabet);
}

1;
__END__

=head1 NAME

Mojolicious::Plugin::Heimdall::Random - Secure random token and password generation

=head1 SYNOPSIS

  my $rnd = $c->heimdall->random;
  my $token = $rnd->token(32);
  my $pass  = $rnd->password(20);
  my $str   = $rnd->string(16, 'abcdef0123456789');

=head1 DESCRIPTION

Wraps L<Crypt::URandom::Token> (which uses L<Crypt::URandom> as its
entropy source) to provide cryptographically secure random strings.
Rejection sampling prevents modulo bias.

=cut
