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

Holds references to all sub-modules (Password, Random, Crypto, JWT, Auth)
and exposes them as accessor methods. Use C<$c-E<gt>heimdall-E<gt>password>
instead of C<$c-E<gt>heimdall-E<gt>{password}>.

=cut
