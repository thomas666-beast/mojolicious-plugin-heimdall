use Mojo::Base -strict;
use Test::More;
use Mojolicious;
use Mojolicious::Plugin::Heimdall;

my $app = Mojolicious->new;
$app->plugin('Heimdall');
my $jwt = $app->heimdall->{jwt};

# HS256 round-trip
my $payload = { sub => 42, role => 'admin' };
my $token = $jwt->encode($payload, 'shared-secret', 'HS256');
ok(defined $token, 'HS256 token generated');
like($token, qr/^[\w-]+\.[\w-]+\.[\w-]+$/, 'JWS has 3 segments');

my $decoded = $jwt->decode($token, 'shared-secret', ['HS256']);
is_deeply($decoded, $payload, 'HS256 round-trip');

# Wrong key fails
eval { $jwt->decode($token, 'wrong-secret', ['HS256']) };
ok($@, 'wrong key rejected');

# Algorithm confusion: token signed with HS256 must be rejected
# when only RS256 is accepted
eval { $jwt->decode($token, 'shared-secret', ['RS256']) };
ok($@, 'algorithm confusion blocked by accepted_alg');

# JWE round-trip
my $jwe = $jwt->encode($payload, 'shared-secret', 'PBES2-HS256+A128KW', 'A128GCM');
ok(defined $jwe, 'JWE token generated');
my @parts = split /\./, $jwe;
is(scalar @parts, 5, 'JWE has 5 segments');

my $jwe_decoded = $jwt->decode_jwe(
  $jwe, 'shared-secret',
  ['PBES2-HS256+A128KW'], ['A128GCM']
);
is_deeply($jwe_decoded, $payload, 'JWE round-trip');

# Tampered JWE fails
my $tampered = $jwe;
$tampered =~ s/\.([^.]+)$/.AAAA/;
eval { $jwt->decode_jwe($tampered, 'shared-secret', ['PBES2-HS256+A128KW'], ['A128GCM']) };
ok($@, 'tampered JWE rejected');

done_testing;
