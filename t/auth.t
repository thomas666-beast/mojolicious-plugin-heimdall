use Mojo::Base -strict, -signatures;
use Test::More;
use Mojolicious;
use Mojolicious::Plugin::Heimdall;

my $app = Mojolicious->new;
my $loads = 0;
my %active = (7 => {id => 7});
$app->plugin('Heimdall', {
  auth => {
    session_key => 'uid',
    load_user   => sub ($app, $id) { ++$loads; return $active{$id} },
  },
});

my $c = $app->build_controller;
$c->session({});

my $auth = $c->heimdall->auth;

ok(!$auth->is_authenticated($c), 'initially not authenticated');
is($auth->current_user($c), undef, 'no current user initially');

$c->session(csrf_token => 'pre-login-token', preferences => 'keep');
$auth->login($c, 7);
ok($auth->is_authenticated($c), 'authenticated after login');
is_deeply($auth->current_user($c), { id => 7 }, 'current_user loads via coderef');
is($c->session->{uid}, 7, 'session stores user id');
is($loads, 1, 'guard and current_user share a single lookup within a request');
ok(!exists $c->session->{csrf_token}, 'login clears pre-login CSRF state');
is($c->session->{preferences}, 'keep', 'login preserves unrelated app session state');

my $next = $app->build_controller;
$next->session({uid => 7});
delete $active{7};
ok(!$auth->require_login($next), 'an account removed between requests is denied');
ok(!exists $next->session->{uid}, 'denied stale user ID is discarded');
is($loads, 2, 'active account is checked again on next request');

$c->session(csrf_token => 'signed-in-token', heimdall_return_to => '/account');
$auth->logout($c);
ok(!$auth->is_authenticated($c), 'not authenticated after logout');
is($auth->current_user($c), undef, 'no current user after logout');
ok(!exists $c->session->{csrf_token}, 'logout clears CSRF state');
ok(!exists $c->session->{heimdall_return_to}, 'logout clears the return target');

my $prod = Mojolicious->new(mode => 'production', moniker => 'a_long_but_predictable_application_name');
$prod->plugin('Heimdall');
my $pc = $prod->build_controller;
my $pa = $pc->heimdall->auth;
eval { $pa->require_login($pc) };
like($@, qr/configure explicit random session secrets/, 'production rejects the application moniker');
$prod->secrets(['short']);
eval { $pa->login($pc, 1) };
like($@, qr/configure explicit random session secrets/, 'production rejects short secrets');
my $test_secret = 'test-key-material-only-not-for-production';
$prod->secrets([$test_secret, 'short-older-key']);
eval { $pa->is_authenticated($pc) };
like($@, qr/configure explicit random session secrets/, 'production rejects short verification keys too');
$prod->secrets([$test_secret]);
$pa->login($pc, 1);
ok($pa->is_authenticated($pc), 'production accepts explicit configured secret');

done_testing;
