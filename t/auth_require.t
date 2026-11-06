use Mojo::Base -strict;
use Test::More;
use Mojolicious;
use Mojolicious::Plugin::Heimdall;

my $app = Mojolicious->new;
$app->plugin('Heimdall', { auth => { session_key => 'uid' } });

my $c = $app->build_controller;
$c->session({});
$c->req->url->parse('/protected');

my $auth = $c->heimdall->auth;

# Not logged in -> require_login redirects and returns false
my $ok = $auth->require_login($c);
ok(!$ok, 'require_login returns false when not authenticated');
is($c->session->{heimdall_return_to}, '/protected', 'return_to stored');

# Log in and retry
$auth->login($c, 1);
ok($auth->require_login($c), 'require_login returns true when authenticated');

# return_to consumes the session entry
is($auth->return_to($c), '/protected', 'return_to returns stored path');
is($auth->return_to($c, '/home'), '/home', 'return_to falls back to default');

done_testing;
