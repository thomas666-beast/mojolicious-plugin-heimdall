package Mojolicious::Plugin::Heimdall::Facade;
use Mojo::Base -base, -signatures;

has [qw(password random crypto jwt auth)];

# Back-compat: $c->heimdall->{password} still works
sub _hashref ($self) {
  return {
    password => $self->password,
    random   => $self->random,
    crypto   => $self->crypto,
    jwt      => $self->jwt,
    auth     => $self->auth,
  };
}

1;

__END__

=head1 NAME

Mojolicious::Plugin::Heimdall::Facade - Unified entry point for Heimdall

=head1 SYNOPSIS

  my $h = $c->heimdall;
  my $hash = $h->password->hash($plain);
  my $tok  = $h->random->token(32);
  my $jwt  = $h->jwt->encode({ sub => 1 }, $secret, 'HS256');
  $h->auth->login($c, $user->id);

=head1 DESCRIPTION

Holds references to all submodules and exposes them as accessor methods.

=head1 ATTRIBUTES

L<Mojolicious::Plugin::Heimdall::Facade> implements the following
attributes.

=head2 password

  my $pw = $h->password;

L<Mojolicious::Plugin::Heimdall::Password> instance.

=head2 random

  my $rnd = $h->random;

L<Mojolicious::Plugin::Heimdall::Random> instance.

=head2 crypto

  my $crypto = $h->crypto;

L<Mojolicious::Plugin::Heimdall::Crypto> instance.

=head2 jwt

  my $jwt = $h->jwt;

L<Mojolicious::Plugin::Heimdall::JWT> instance.

=head2 auth

  my $auth = $h->auth;

L<Mojolicious::Plugin::Heimdall::Auth> instance.

=head1 SEE ALSO

L<Mojolicious::Plugin::Heimdall>.

=cut
