use Mojo::Base -strict;
use Test::More;
use Mojolicious;
use Mojolicious::Plugin::Heimdall;

my $app = Mojolicious->new;
$app->plugin('Heimdall');
my $jwt = $app->build_controller->heimdall->jwt;

my $secret  = '0123456789abcdef0123456789abcdef';  # 32 bytes for HS256
my $payload = { sub => 42, role => 'admin' };

# --- JWS / HS256 round-trip ---
my $token = $jwt->encode($payload, $secret, 'HS256');
ok(defined $token, 'HS256 token generated');
like($token, qr/^[\w-]+\.[\w-]+\.[\w-]+$/, 'JWS has 3 segments');

my $decoded = $jwt->decode($token, $secret, ['HS256']);
is_deeply($decoded, $payload, 'HS256 round-trip');

# Wrong key rejected
eval { $jwt->decode($token, 'wrong-secret-32bytes-long!!!!!!', ['HS256']) };
ok($@, 'wrong HMAC key rejected');

# Algorithm confusion: token signed with HS256 must be rejected when RS256 is required
eval { $jwt->decode($token, $secret, ['RS256']) };
ok($@, 'algorithm confusion blocked by accepted_alg');

# --- JWE / PBES2 + A128GCM round-trip ---
my $jwe = $jwt->encode($payload, $secret, 'PBES2-HS256+A128KW', 'A128GCM');
ok(defined $jwe, 'JWE token generated');
my @parts = split /\./, $jwe;
is(scalar @parts, 5, 'JWE has 5 segments');

my $jwe_decoded = $jwt->decode_jwe(
  $jwe, $secret,
  ['PBES2-HS256+A128KW'], ['A128GCM']
);
is_deeply($jwe_decoded, $payload, 'JWE round-trip');

# accepted_alg enforcement: token alg is PBES2-HS256+A128KW, we only allow RSA-OAEP
eval {
  $jwt->decode_jwe($jwe, $secret, ['RSA-OAEP'], ['A128GCM']);
};
ok($@, 'JWE rejected when accepted_alg does not match token alg');

# accepted_enc enforcement: token enc is A128GCM, we only allow A256GCM
eval {
  $jwt->decode_jwe($jwe, $secret, ['PBES2-HS256+A128KW'], ['A256GCM']);
};
ok($@, 'JWE rejected when accepted_enc does not match token enc');

my %policy = (alg => 'HS256', issuer => 'https://issuer.example.test', audience => 'example-api');
my %access = (iss => $policy{issuer}, aud => $policy{audience}, sub => '42', exp => time + 300);
my $access_jws = $jwt->encode(\%access, $secret, 'HS256');
is_deeply($jwt->verify_access_token($access_jws, $secret, %policy), \%access, 'valid access token');
my $array_aud = $jwt->encode({%access, aud => ['another-api', 'example-api']}, $secret, 'HS256');
is($jwt->verify_access_token($array_aud, $secret, %policy)->{sub}, '42', 'allow matching array audience');

for my $claim (qw(exp iss aud sub)) {
  my %missing = %access;
  delete $missing{$claim};
  my $candidate = $jwt->encode(\%missing, $secret, 'HS256');
  eval { $jwt->verify_access_token($candidate, $secret, %policy) };
  like($@, qr/invalid access token/, "missing $claim rejected");
}
for my $case (
  ['expired', exp => time - 60],
  ['not yet valid', nbf => time + 120],
  ['wrong issuer', iss => 'https://another-issuer.example.test'],
  ['wrong audience', aud => 'another-api'],
  ['empty subject', sub => ''],
) {
  my ($label, $claim, $value) = @$case;
  my $candidate = $jwt->encode({%access, $claim => $value}, $secret, 'HS256');
  eval { $jwt->verify_access_token($candidate, $secret, %policy) };
  like($@, qr/invalid access token/, "$label rejected");
}

eval { $jwt->verify_access_token($access_jws, $secret, %policy, alg => 'RS256') };
like($@, qr/invalid access token/, 'strict verifier enforces the configured signature algorithm');
eval { $jwt->verify_access_token($access_jws, 'short-key', %policy) };
like($@, qr/at least 32 bytes/, 'strict verifier enforces minimum HMAC key length');
eval { $jwt->verify_access_token($jwe, $secret, %policy) };
like($@, qr/expected a compact signed JWT/, 'strict verifier does not accept JWE as an access token');
eval { $jwt->verify_access_token($access_jws, $secret, alg => 'HS256', issuer => $policy{issuer}) };
like($@, qr/expected issuer and audience/, 'policy must be explicitly configured');

my $keys = $app->heimdall->crypto->rsa_generate;
my $signed_rs = $jwt->encode(\%access, \$keys->{private_pem}, 'RS256');
is_deeply($jwt->verify_access_token($signed_rs, \$keys->{public_pem}, %policy, alg => 'RS256'),
  \%access, 'strict verifier works with RSA public keys');

done_testing;
