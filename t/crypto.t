use Mojo::Base -strict;
use Test::More;
use Mojolicious;
use Mojolicious::Plugin::Heimdall;
use Crypt::PRNG qw(random_bytes);
use Encode qw(encode_utf8);

my $app = Mojolicious->new;
$app->plugin('Heimdall');
my $crypto = $app->heimdall->{crypto};

# RSA round-trip
my $keys = $crypto->rsa_generate(2048);
like($keys->{public_pem},  qr/BEGIN RSA PUBLIC KEY/, 'public PEM');
like($keys->{private_pem}, qr/BEGIN RSA PRIVATE KEY|BEGIN PRIVATE KEY/, 'private PEM');

my $plain = "sensitive data \x{263A}";
my $plain_bytes = encode_utf8($plain);
my $ct = $crypto->rsa_encrypt($plain_bytes, $keys->{public_pem});
isnt($ct, $plain_bytes, 'ciphertext differs from plaintext');
is($crypto->rsa_decrypt($ct, $keys->{private_pem}), $plain_bytes, 'RSA round-trip');

# AES-GCM round-trip
my $key = random_bytes(32);
my $blob = $crypto->aes_gcm_encrypt($plain_bytes, $key, 'aad-context');
ok(defined $blob->{iv} && defined $blob->{tag}, 'GCM returns iv and tag');
is($crypto->aes_gcm_decrypt($blob, $key, 'aad-context'), $plain_bytes, 'GCM round-trip');

# Tampered ciphertext must fail
my $tampered = { %$blob };
$tampered->{ciphertext} = substr($blob->{ciphertext}, 0, -4) . 'AAAA';
ok(!defined $crypto->aes_gcm_decrypt($tampered, $key, 'aad-context'), 'tampered GCM rejected');

# Wrong AAD must fail
ok(!defined $crypto->aes_gcm_decrypt($blob, $key, 'wrong-aad'), 'wrong AAD rejected');

done_testing;
