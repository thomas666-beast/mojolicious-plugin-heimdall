use Mojo::Base -strict, -signatures;
use Test::More;
use Mojolicious;
use Mojolicious::Plugin::Heimdall;

my $app = Mojolicious->new;
$app->plugin('Heimdall', {
  auth => {
    session_key => 'uid',
    load_user   => sub ($app, $id) { return { id => $id } },
  },
});

my $c = $app->build_controller;
$c->session({});

my $auth = $c->heimdall->{auth};

ok(!$auth->is_authenticated($c), 'initially not authenticated');
is($auth->current_user($c), undef, 'no current user initially');

$auth->login($c, 7);
ok($auth->is_authenticated($c), 'authenticated after login');
is_deeply($auth->current_user($c), { id => 7 }, 'current_user loads via coderef');
is($c->session->{uid}, 7, 'session stores user id');

$auth->logout($c);
ok(!$auth->is_authenticated($c), 'not authenticated after logout');
is($auth->current_user($c), undef, 'no current user after logout');

done_testing;
