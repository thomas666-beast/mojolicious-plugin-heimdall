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

=head1 NAME

Mojolicious::Plugin::Heimdall - Unified security toolbox: password hashing, encryption, JWT, and session auth

=head1 SYNOPSIS

  # Load in a Mojolicious application
  $app->plugin('Heimdall');

  # Use the unified facade in a controller
  my $h = $c->heimdall;

  # Password hashing (Argon2 by default, Bcrypt verification supported)
  my $hash = $h->password->hash($plain);
  my $ok   = $h->password->verify($plain, $hash);

  # Secure random strings
  my $token = $h->random->token(32);
  my $pass  = $h->random->password(20);

  # RSA and AES-GCM encryption
  my $keys   = $h->crypto->rsa_generate(2048);
  my $cipher = $h->crypto->rsa_encrypt($plain, $keys->{public_pem});

  # JWT (JWS + JWE)
  my $jws = $h->jwt->encode({ sub => 42 }, $secret, 'HS256');

  # Session authentication
  $h->auth->login($c, $user_id);
  my $user = $h->auth->current_user($c);

=head1 DESCRIPTION

L<Mojolicious::Plugin::Heimdall> is a security plugin for L<Mojolicious>
applications that wraps several audited CPAN security modules behind a
single unified API. The name comes from Heimdall, the ever-watchful guardian
of the Bifröst bridge in Norse mythology, reflecting the plugin's role as a
constant sentinel at the application's entry points.

All submodules are reached through the C<$c-E<gt>heimdall> facade, which
returns a L<Mojolicious::Plugin::Heimdall::Facade> instance whose accessors
expose the modules below.

=head2 Submodules

=over 4

=item L<Mojolicious::Plugin::Heimdall::Password>

Password hashing. Uses L<Crypt::Passphrase> internally, generating new hashes
with Argon2 by default while verifying Bcrypt hashes. The C<password_encoder>
and C<password_validators> options can be overridden at plugin load time.

=item L<Mojolicious::Plugin::Heimdall::Random>

Cryptographically secure randomness. Built on L<Crypt::URandom::Token>,
exposing C<token>, C<password>, and C<string>. Rejection sampling is used to
avoid modulo bias.

=item L<Mojolicious::Plugin::Heimdall::Crypto>

Asymmetric and symmetric encryption. RSA uses L<Crypt::PK::RSA> from
L<CryptX> with OAEP padding; symmetric encryption uses the one-shot AES-GCM
interface for authenticated encryption. Requires C<CryptX> E<gt>= 0.088_001
(fixes CVE-2026-13758 and CVE-2026-41564).

=item L<Mojolicious::Plugin::Heimdall::JWT>

Full JWS and JWE support via L<Crypt::JWT>. Decoding requires an explicit
C<accepted_alg>, preventing algorithm confusion attacks.

=item L<Mojolicious::Plugin::Heimdall::Auth>

Session authentication. Provides C<login>, C<logout>, C<current_user>, and
C<require_login> on top of L<Mojolicious::Sessions>. Only the user ID is
stored in the session; the user object is loaded lazily through the
C<load_user> callback.

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

Array reference of validators used to verify existing hashes. Defaults to
C<[ 'Bcrypt', 'Argon2' ]>.

=item auth

Hash reference with C<session_key> (default C<user_id>) and C<load_user>
(coderef C<< sub ($app, $id) { ... } >>).

=back

=head1 CONFIGURATION EXAMPLE

  $app->plugin('Heimdall', {
    password_encoder    => 'Bcrypt',
    password_validators => ['Bcrypt'],
    auth => {
      session_key => 'uid',
      load_user   => sub ($app, $id) {
        return $app->users->find($id);
      },
    },
  });

=head1 SECURITY NOTES

=over 4

=item * C<decode> in L<Mojolicious::Plugin::Heimdall::JWT> always passes
C<accepted_alg> to L<Crypt::JWT>, blocking RS256→HS256 confusion attacks.

=item * C<aes_gcm_decrypt> returns C<undef> on authentication failure; never
treat C<undef> as success.

=item * HMAC keys for HS256 must be at least 32 bytes (RFC 7518).

=item * Store RSA private keys and AES keys outside the application tree.

=back

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<https://mojolicious.org>,
L<Crypt::Passphrase>, L<Crypt::URandom::Token>, L<CryptX>, L<Crypt::JWT>.

=cut
