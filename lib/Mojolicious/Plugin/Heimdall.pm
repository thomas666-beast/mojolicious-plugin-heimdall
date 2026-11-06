package Mojolicious::Plugin::Heimdall;
use Mojolicious;
use Mojo::Base 'Mojolicious::Plugin', -signatures;

our $VERSION = '0.001';

sub register ($self, $app, $conf) {
  require Mojolicious::Plugin::Heimdall::Password;

  my $password = Mojolicious::Plugin::Heimdall::Password->new(
    encoder    => $conf->{password_encoder}    // 'Argon2',
    validators => $conf->{password_validators} // [ 'Bcrypt', 'Argon2' ],
  );

  $app->helper(heimdall => sub ($c) {
    return { password => $password };
  });

  return $self;
}
1;
__END__

=head1 NAME

Mojolicious::Plugin::Heimdall - Security toolbox for Mojolicious

=head1 SYNOPSIS

  # In a Mojolicious application
  $app->plugin('Heimdall');

=head1 DESCRIPTION

Heimdall is a unified-API security plugin for the Mojolicious web framework.
It bundles password hashing, symmetric/asymmetric encryption, secure random
generation, JWT (JWS + JWE), and session authentication behind one facade.

B<This is an early skeleton.> The facade API is not yet implemented.

=head1 METHODS

L<Mojolicious::Plugin::Heimdall> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 register

  $plugin->register(Mojolicious->new);

Register plugin in L<Mojolicious> application.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<https://mojolicious.org>.

=cut
