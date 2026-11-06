package Mojolicious::Plugin::Heimdall;
use Mojolicious;
use Mojo::Base 'Mojolicious::Plugin', -signatures;

our $VERSION = '0.001';

sub register ($self, $app, $conf) {
  require Mojolicious::Plugin::Heimdall::Password;
  require Mojolicious::Plugin::Heimdall::Random;
  require Mojolicious::Plugin::Heimdall::Crypto;
  require Mojolicious::Plugin::Heimdall::JWT;
  require Mojolicious::Plugin::Heimdall::Auth;
  require Mojolicious::Plugin::Heimdall::Facade;

  my $password = Mojolicious::Plugin::Heimdall::Password->new(
    encoder    => $conf->{password_encoder}    // 'Argon2',
    validators => $conf->{password_validators} // [ 'Bcrypt', 'Argon2' ],
  );
  my $random = Mojolicious::Plugin::Heimdall::Random->new;
  my $crypto = Mojolicious::Plugin::Heimdall::Crypto->new;
  my $jwt    = Mojolicious::Plugin::Heimdall::JWT->new;

  my %auth_conf = %{ $conf->{auth} // {} };
  my $auth = Mojolicious::Plugin::Heimdall::Auth->new(
    session_key => $auth_conf{session_key} // 'user_id',
    load_user   => $auth_conf{load_user},
  );

  my $facade = Mojolicious::Plugin::Heimdall::Facade->new(
    password => $password,
    random   => $random,
    crypto   => $crypto,
    jwt      => $jwt,
    auth     => $auth,
  );

  $app->helper(heimdall => sub ($c) { return $facade });

  return $self;
}

1;
__END__

=encoding utf8

=head1 NAME

Mojolicious::Plugin::Heimdall - Unified security toolbox for Mojolicious

=head1 SYNOPSIS

  $app->plugin('Heimdall');

  my $h = $c->heimdall;

  my $hash  = $h->password->hash($plain);
  my $ok    = $h->password->verify($plain, $hash);
  my $token = $h->random->token(32);
  my $jws   = $h->jwt->encode({ sub => 42 }, $secret, 'HS256');
  $h->auth->login($c, $user_id);

=head1 DESCRIPTION

L<Mojolicious::Plugin::Heimdall> is a security toolbox for L<Mojolicious>
applications. It wraps audited CPAN modules behind one facade reached via
C<$c-E<gt>heimdall>, which returns a
L<Mojolicious::Plugin::Heimdall::Facade>.

The name comes from Heimdall, the ever-watchful guardian of the Bifroest
bridge in Norse mythology.

=head2 Submodules

=over 4

=item L<Mojolicious::Plugin::Heimdall::Password>

Password hashing via L<Crypt::Passphrase> (Argon2 default, Bcrypt verify).

=item L<Mojolicious::Plugin::Heimdall::Random>

Secure random tokens, passwords, and strings via L<Crypt::URandom::Token>.

=item L<Mojolicious::Plugin::Heimdall::Crypto>

RSA (OAEP) and AES-GCM via L<CryptX>.

=item L<Mojolicious::Plugin::Heimdall::JWT>

JWS and JWE via L<Crypt::JWT>.

=item L<Mojolicious::Plugin::Heimdall::Auth>

Session authentication on top of L<Mojolicious::Sessions>.

=back

=head1 METHODS

L<Mojolicious::Plugin::Heimdall> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 register

  $plugin->register(Mojolicious->new);
  $plugin->register(Mojolicious->new, \%config);

Register the plugin in a L<Mojolicious> application and install the
C<heimdall> helper. Recognized configuration keys:

=over 4

=item password_encoder

Encoder used for new password hashes. Defaults to C<Argon2>.

=item password_validators

Array reference of validators. Defaults to C<[ 'Bcrypt', 'Argon2' ]>.

=item auth

Hash reference with C<session_key> (default C<user_id>) and C<load_user>
(coderef C<< sub ($app, $id) { ... } >>).

=back

=head1 SECURITY NOTES

=over 4

=item * C<decode> in L<Mojolicious::Plugin::Heimdall::JWT> always passes
C<accepted_alg> to L<Crypt::JWT>, blocking algorithm confusion attacks.

=item * C<aes_gcm_decrypt> returns C<undef> on authentication failure.

=item * HMAC keys for HS256 must be at least 32 bytes (RFC 7518).

=back

=head1 SEE ALSO

L<Mojolicious>, L<Crypt::Passphrase>, L<Crypt::URandom::Token>, L<CryptX>,
L<Crypt::JWT>, L<https://mojolicious.org>.

=cut
