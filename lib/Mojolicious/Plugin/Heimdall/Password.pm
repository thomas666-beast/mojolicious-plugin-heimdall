package Mojolicious::Plugin::Heimdall::Password;
use Mojo::Base -base, -signatures;

use Crypt::Passphrase;

has 'passphrase';

sub new ($class, %args) {
  my $encoder = $args{encoder} // 'Argon2';
  my $validators = $args{validators} // [ 'Bcrypt', 'Argon2' ];

  my $self = $class->SUPER::new(%args);
  $self->passphrase(
    Crypt::Passphrase->new(
      encoder    => $encoder,
      validators => $validators,
    )
  );
  return $self;
}

sub hash ($self, $plain) {
  return $self->passphrase->hash_password($plain);
}

sub verify ($self, $plain, $hash) {
  return $self->passphrase->verify_password($plain, $hash);
}

sub needs_rehash ($self, $hash) {
  return $self->passphrase->needs_rehash($hash);
}

1;
__END__

=head1 NAME

Mojolicious::Plugin::Heimdall::Password - Multi-algorithm password hashing

=head1 SYNOPSIS

  my $pw = $c->heimdall->password;
  my $hash = $pw->hash($plain);
  my $ok   = $pw->verify($plain, $hash);

=head1 DESCRIPTION

Wraps L<Crypt::Passphrase> to provide bcrypt, Argon2, and PBKDF2
hashing behind a single interface. New hashes use the configured
encoder; existing hashes are verified against all configured validators.

=cut
