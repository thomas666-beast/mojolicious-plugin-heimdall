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

Wraps L<Crypt::Passphrase> to provide bcrypt, Argon2, and PBKDF2 hashing
behind a single interface. New hashes use the configured encoder; existing
hashes are verified against all configured validators.

=head1 ATTRIBUTES

=head2 passphrase

  my $cp = $pw->passphrase;

Underlying L<Crypt::Passphrase> object.

=head1 METHODS

=head2 new

  my $pw = Mojolicious::Plugin::Heimdall::Password->new(%args);

Constructor. Accepts C<encoder> (default C<Argon2>) and C<validators>
(default C<[ 'Bcrypt', 'Argon2' ]>).

=head2 hash

  my $hash = $pw->hash($plain);

Hash a plaintext password using the configured encoder.

=head2 verify

  my $ok = $pw->verify($plain, $hash);

Verify a plaintext password against a stored hash. Returns true on match.

=head2 needs_rehash

  my $bool = $pw->needs_rehash($hash);

Check whether a hash should be regenerated with current parameters.

=head1 SEE ALSO

L<Crypt::Passphrase>, L<Mojolicious::Plugin::Heimdall>.

=cut
