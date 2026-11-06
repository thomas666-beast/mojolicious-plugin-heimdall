use Mojo::Base -strict;
use Test::More;
use Mojolicious;
use Mojolicious::Plugin::Heimdall;

my $app = Mojolicious->new;
$app->plugin('Heimdall');

my $rnd = $app->heimdall->{random};

# token
my $t = $rnd->token;
is(length $t, 44, 'default token length 44');
like($t, qr/^[A-Za-z0-9]+$/, 'token is alphanumeric');
isnt($rnd->token, $t, 'two tokens differ');

my $t2 = $rnd->token(16);
is(length $t2, 16, 'custom token length');

# password
my $p = $rnd->password;
is(length $p, 16, 'default password length 16');
like($p, qr/[A-Z]/, 'password has uppercase');
like($p, qr/[a-z]/, 'password has lowercase');
like($p, qr/[0-9]/, 'password has digit');
like($p, qr/[!@#\$%^&*()\-_=+\[\]{};:,.<>?]/, 'password has symbol');

# string with custom alphabet
my $s = $rnd->string(10, 'ab');
is(length $s, 10, 'string length');
like($s, qr/^[ab]+$/, 'string uses custom alphabet');

done_testing;
