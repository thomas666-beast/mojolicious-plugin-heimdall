use Mojo::Base -strict;
use Test::More;
use Mojolicious;
use Mojolicious::Plugin::Heimdall;

my $app = Mojolicious->new;
$app->plugin('Heimdall');

my $h = $app->build_controller->heimdall;
my $pw = $h->password;

# Argon2 default encoder
my $hash = $pw->hash('s3cr3t');
ok(defined $hash, 'hash returns a value');
ok($pw->verify('s3cr3t', $hash), 'correct password verifies');
ok(!$pw->verify('wrong', $hash), 'wrong password rejected');

# hash is not plaintext
isnt($hash, 's3cr3t', 'hash is not plaintext');

# Different calls produce different hashes (salt)
my $hash2 = $pw->hash('s3cr3t');
isnt($hash, $hash2, 'salts produce different hashes');
ok($pw->verify('s3cr3t', $hash2), 'second hash also verifies');

done_testing;
