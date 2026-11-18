use Mojo::Base -strict;
use Test::More;
use Mojolicious;
use Mojolicious::Plugin::Heimdall;

my $app = Mojolicious->new;
$app->plugin('Heimdall', { auth => { session_key => 'uid' } });

my $c = $app->build_controller;
$c->session({});
$c->req->method('GET');
$c->req->url->parse('/protected?page=2');
$c->req->url->base->parse('https://app.example.test/');

my $auth = $c->heimdall->auth;

# Not logged in -> require_login redirects and returns false
my $ok = $auth->require_login($c);
ok(!$ok, 'require_login returns false when not authenticated');
is($c->session->{heimdall_return_to}, '/protected?page=2', 'return_to stores only path and query');

# Log in and retry
$auth->login($c, 1);
ok($auth->require_login($c), 'require_login returns true when authenticated');

# return_to consumes the session entry
is($auth->return_to($c), '/protected?page=2', 'return_to returns stored path');
is($auth->return_to($c, '/home'), '/home', 'return_to falls back to default');

$c->session(heimdall_return_to => 'https://external.example.test/landing');
is($auth->return_to($c, '/home'), '/home', 'legacy absolute destination is rejected');
is($auth->return_to($c, 'https://external.example.test/landing'), '/', 'fallback must also be local');

my $post = $app->build_controller;
$post->req->method('POST');
$post->req->url->parse('/update');
ok(!$auth->require_login($post), 'anonymous POST is denied');
ok(!exists $post->session->{heimdall_return_to}, 'non-navigation requests are not saved for replay');

done_testing;
