use Mojo::Base -strict;
use Test::More;
use Mojolicious;
use Mojolicious::Plugin::Heimdall;
use Mojolicious::Plugin::Heimdall::Password;
use Mojolicious::Plugin::Heimdall::Random;
use Mojolicious::Plugin::Heimdall::Crypto;
use Mojolicious::Plugin::Heimdall::JWT;
use Mojolicious::Plugin::Heimdall::Auth;
use Mojolicious::Plugin::Heimdall::Facade;

my $app = Mojolicious->new;
$app->plugin('Heimdall');

my $h = $app->build_controller->heimdall;

isa_ok($h, 'Mojolicious::Plugin::Heimdall::Facade', 'heimdall helper returns Facade');
isa_ok($h->password, 'Mojolicious::Plugin::Heimdall::Password', 'password accessor');
isa_ok($h->random,   'Mojolicious::Plugin::Heimdall::Random',   'random accessor');
isa_ok($h->crypto,   'Mojolicious::Plugin::Heimdall::Crypto',   'crypto accessor');
isa_ok($h->jwt,      'Mojolicious::Plugin::Heimdall::JWT',      'jwt accessor');
isa_ok($h->auth,     'Mojolicious::Plugin::Heimdall::Auth',     'auth accessor');

# Chainable API
my $hash = $h->password->hash('test');
ok($h->password->verify('test', $hash), 'facade password chain works');

done_testing;
