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

=head1 NAME

Mojolicious::Plugin::Heimdall::JWT - Full JWS and JWE support

=head1 SYNOPSIS

  my $jwt = $c->heimdall->jwt;

  # JWS (signed)
  my $token = $jwt->encode({ sub => 42 }, 'secret', 'HS256');
  my $claims = $jwt->decode($token, 'secret', ['HS256']);

  # JWE (encrypted)
  my $jwe = $jwt->encode({ sub => 42 }, 'secret', 'PBES2-HS256+A128KW', 'A128GCM');
  my $claims = $jwt->decode_jwe($jwe, 'secret', ['PBES2-HS256+A128KW'], ['A128GCM']);

=head1 SECURITY

C<decode> requires C<accepted_alg> and always passes it to Crypt::JWT.
This prevents algorithm confusion attacks (e.g. RS256→HS256) [citation:1].

When C<key> is a PEM or DER string, it is automatically wrapped in a
SCALAR ref, because Crypt::JWT interprets bare scalars as raw octet
strings (HMAC secrets). A bare PEM string would otherwise be misused
as an HMAC key [citation:1].

=cut
