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

done_testing;
