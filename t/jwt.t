use Mojo::Base -strict;
use Test::More;
use Mojolicious;
use Mojolicious::Plugin::Heimdall;

my $app = Mojolicious->new;
$app->plugin('Heimdall');
my $jwt = $app->heimdall->{jwt};

my $secret = '0123456789abcdef0123456789abcdef';  # 32 bytes for HS256
my $payload = { sub => 42, role => 'admin' };

# HS256 round-trip
my $token = $jwt->encode($payload, $secret, 'HS256');
ok(defined $token, 'HS256 token generated');
like($token, qr/^[\w-]+\.[\w-]+\.[\w-]+$/, 'JWS has 3 segments');

my $decoded = $jwt->decode($token, $secret, ['HS256']);
is_deeply($decoded, $payload, 'HS256 round-trip');

# Wrong key fails
eval { $jwt->decode($token, 'wrong-secret-32bytes-long!!!!!!', ['HS256']) };
ok($@, 'wrong key rejected');

# Algorithm confusion blocked
eval { $jwt->decode($token, $secret, ['RS256']) };
ok($@, 'algorithm confusion blocked by accepted_alg');

# JWE round-trip
my $jwe = $jwt->encode($payload, $secret, 'PBES2-HS256+A128KW', 'A128GCM');
ok(defined $jwe, 'JWE token generated');
my @parts = split /\./, $jwe;
is(scalar @parts, 5, 'JWE has 5 segments');

my $jwe_decoded = $jwt->decode_jwe(
  $jwe, $secret,
  ['PBES2-HS256+A128KW'], ['A128GCM']
);
is_deeply($jwe_decoded, $payload, 'JWE round-trip');

# Tampered JWE fails
my $tampered = $jwe;
my @jwe_parts = split /\./, $tampered;
# Flip a character in the ciphertext (4th segment, index 3)
$jwe_parts[3] = substr($jwe_parts[3], 0, -1) . ($jwe_parts[3] =~ /A$/ ? 'B' : 'A');
$tampered = join '.', @jwe_parts;

my $tamper_ok = eval {
  my $r = $jwt->decode_jwe($tampered, $secret, ['PBES2-HS256+A128KW'], ['A128GCM']);
  # If no exception, the result must NOT match the original payload
  return 0 if defined $r && ref $r eq 'HASH'
    && defined $r->{sub} && $r->{sub} == 42;
  return 1;
};
ok($tamper_ok, 'tampered JWE rejected (exception or mismatched payload)');

done_testing;
