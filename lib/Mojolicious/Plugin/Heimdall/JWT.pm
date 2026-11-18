package Mojolicious::Plugin::Heimdall::JWT;
use Mojo::Base -base, -signatures;

use Carp qw(croak);
use Crypt::JWT qw(encode_jwt decode_jwt);

sub encode ($self, $payload, $key, $alg = 'HS256', $enc = undef) {
  my %args = (payload => $payload, key => $key, alg => $alg);
  $args{enc} = $enc if defined $enc;
  return encode_jwt(%args);
}

sub decode ($self, $token, $key, $accepted_alg = ['HS256']) {
  croak 'Heimdall: accepted_alg must be defined' unless defined $accepted_alg;
  return decode_jwt(
    token        => $token,
    key          => $key,
    accepted_alg => $accepted_alg,
  );
}

sub decode_jwe ($self, $token, $key, $accepted_alg, $accepted_enc) {
  croak 'Heimdall: accepted_alg and accepted_enc must be defined'
    unless defined $accepted_alg && defined $accepted_enc;
  return decode_jwt(
    token        => $token,
    key          => $key,
    accepted_alg => $accepted_alg,
    accepted_enc => $accepted_enc,
  );
}

sub verify_access_token ($self, $token, $key, %policy) {
  my ($alg, $issuer, $audience) = delete @policy{qw(alg issuer audience)};
  croak 'Heimdall: unknown access token policy option' if keys %policy;
  croak 'Heimdall: configure one signed JWT algorithm'
    unless defined $alg && !ref($alg)
      && $alg =~ /\A(?:[HRP]S(?:256|384|512)|ES(?:256|384|512|256K)|EdDSA)\z/;
  croak 'Heimdall: configure an expected issuer and audience'
    if grep { !defined($_) || ref($_) || !length($_) } ($issuer, $audience);
  if ($alg =~ /\AHS(256|384|512)\z/) {
    my $minimum = $1 / 8;
    croak "Heimdall: $alg requires a raw key of at least $minimum bytes"
      unless defined $key && !ref($key) && $key !~ /[^\x00-\xff]/
        && length($key) >= $minimum;
  }
  croak 'Heimdall: expected a compact signed JWT'
    unless defined $token && !ref($token) && length($token) <= 16384
      && $token =~ /\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/;
  my $claims = eval {
    decode_jwt(
      token        => $token,
      key          => $key,
      accepted_alg => [$alg],
      verify_exp   => 1,
      verify_iss   => $issuer,
      verify_aud   => $audience,
    );
  };
  croak 'Heimdall: invalid access token'
    unless ref($claims) eq 'HASH' && defined $claims->{sub}
      && !ref($claims->{sub}) && length($claims->{sub});
  return $claims;
}

1;

__END__

=encoding utf8

=head1 NAME

Mojolicious::Plugin::Heimdall::JWT - Full JWS and JWE support

=head1 SYNOPSIS

  my $jwt = $c->heimdall->jwt;

  my $token  = $jwt->encode({ sub => 42 }, $secret, 'HS256');
  my $claims = $jwt->decode($token, $secret, ['HS256']);

  my $jwe    = $jwt->encode({ sub => 42 }, $secret,
                            'PBES2-HS256+A128KW', 'A128GCM');
  my $claims = $jwt->decode_jwe($jwe, $secret,
                                ['PBES2-HS256+A128KW'], ['A128GCM']);

=head1 DESCRIPTION

Wraps L<Crypt::JWT> for JWS signing/verification and JWE
encryption/decryption.

=head1 SECURITY

C<decode> defaults to HS256. Always pin the expected algorithm to match
your key. C<decode_jwe> requires both algorithm constraints.
Use C<verify_access_token> for API authentication.

HMAC keys for HS256 must be at least 32 bytes (RFC 7518).

=head1 METHODS

=head2 encode

  my $token = $jwt->encode($payload, $key, $alg, $enc);

Encode a payload. For JWS, omit C<$enc>. For JWE, pass C<$enc> (e.g.
C<A128GCM>).

=head2 decode

  my $claims = $jwt->decode($token, $key, \@accepted_alg);

Low-level verification. C<\@accepted_alg> defaults to C<['HS256']>;
use an explicit allowlist for other key types. This method does not
require an expiration, issuer or audience.

=head2 decode_jwe

  my $claims = $jwt->decode_jwe($token, $key,
                                \@accepted_alg, \@accepted_enc);

Decrypt a JWE token. Both C<\@accepted_alg> and C<\@accepted_enc> are
mandatory.

=head2 verify_access_token

  my $claims = $jwt->verify_access_token(
    $bearer, $key, alg => 'HS256',
    issuer => 'https://issuer.example', audience => 'my-api',
  );

Validate a compact signed JWT of at most 16 KiB against a server-configured
algorithm, issuer and audience. Require a valid expiration and a nonempty
scalar subject. HMAC keys must be raw bytes at least as long as the
algorithm's digest. For PEM keys pass a scalar reference or a supported
key object. The method throws on invalid tokens or configuration; handle
invalid bearer tokens as HTTP 401 without exposing exception details.
The caller still must resolve the subject to a current account and check
permissions. Use a distinct audience for each token purpose.

=head1 SEE ALSO

L<Crypt::JWT>, L<Mojolicious::Plugin::Heimdall>.

=cut
