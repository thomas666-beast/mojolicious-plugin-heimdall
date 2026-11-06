package Mojolicious::Plugin::Heimdall::JWT;
use Mojo::Base -base, -signatures;

use Crypt::JWT qw(encode_jwt decode_jwt);

sub encode ($self, $payload, $key, $alg = 'HS256', $enc = undef) {
  my %args = (payload => $payload, key => $key, alg => $alg);
  $args{enc} = $enc if defined $enc;
  return encode_jwt(%args);
}

sub decode ($self, $token, $key, $accepted_alg = ['HS256']) {
  # HMAC keys are bare scalars; PEM keys need a SCALAR ref
  my $k = ref $key ? $key : $key;
  return decode_jwt(
    token        => $token,
    key          => $k,
    accepted_alg => $accepted_alg,
  );
}

sub decode_jwe ($self, $token, $key, $accepted_alg, $accepted_enc) {
  my $k = ref $key ? $key : $key;
  return decode_jwt(
    token        => $token,
    key          => $k,
    accepted_alg => $accepted_alg,
    accepted_enc => $accepted_enc,
  );
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

C<decode> and C<decode_jwe> require C<accepted_alg>. This blocks algorithm
confusion attacks such as RS256 to HS256.

HMAC keys for HS256 must be at least 32 bytes (RFC 7518).

=head1 METHODS

=head2 encode

  my $token = $jwt->encode($payload, $key, $alg, $enc);

Encode a payload. For JWS, omit C<$enc>. For JWE, pass C<$enc> (e.g.
C<A128GCM>).

=head2 decode

  my $claims = $jwt->decode($token, $key, \@accepted_alg);

Verify a JWS token. C<\@accepted_alg> is mandatory.

=head2 decode_jwe

  my $claims = $jwt->decode_jwe($token, $key,
                                \@accepted_alg, \@accepted_enc);

Decrypt a JWE token. Both C<\@accepted_alg> and C<\@accepted_enc> are
mandatory.

=head1 SEE ALSO

L<Crypt::JWT>, L<Mojolicious::Plugin::Heimdall>.

=cut
