use Mojo::Base -strict;
use Test::More;
use Test::Mojo;
use Mojo::File qw(curfile);

local $ENV{HEIMDALL_SESSION_SECRET} = 'synthetic-session-key-for-the-example-test';
local $ENV{HEIMDALL_ADMIN_PASSWORD} = 'test-only-administrator-password';
local $ENV{HEIMDALL_MEMBER_PASSWORD} = 'test-only-member-password';
local $ENV{MOJO_MODE} = 'testing';
my $script = curfile->dirname->sibling('examples', 'heimdall_demo.pl');
my $t = Test::Mojo->new($script);
my $member = Test::Mojo->new($t->app);
$t->app->log->level('fatal');

sub csrf { return $_[0]->tx->res->dom->at('input[name=csrf_token]')->attr('value') }

$t->get_ok('/')->status_is(302)->header_is(Location => '/account');
$t->get_ok('/account?from=test')->status_is(302)->header_is(Location => '/login');
$t->post_ok('/login' => form => {username => 'admin', password => $ENV{HEIMDALL_ADMIN_PASSWORD}})
  ->status_is(403);

$t->get_ok('/login')->status_is(200)->header_is('Cache-Control', 'no-store');
$t->post_ok('/login' => form => {username => 'admin', password => 'wrong', csrf_token => csrf($t)})
  ->status_is(401)->content_like(qr/Invalid username or password/);
$t->post_ok('/login' => form => {username => 'unknown', password => 'wrong', csrf_token => csrf($t)})
  ->status_is(401)->content_like(qr/Invalid username or password/);
my $pre_login = csrf($t);
$t->post_ok('/login' => form => {
    username => 'admin', password => $ENV{HEIMDALL_ADMIN_PASSWORD}, csrf_token => $pre_login,
  })->status_is(303)->header_is(Location => '/account?from=test');

$t->get_ok('/account')->status_is(200)->content_like(qr/Hello, admin/);
my $signed_in = csrf($t);
$t->get_ok('/admin')->status_is(200)->content_is('Admin area');
$t->get_ok('/logout')->status_is(404);
$t->post_ok('/logout' => form => {csrf_token => $pre_login})->status_is(403);
$t->post_ok('/logout')->status_is(403);
$t->post_ok('/logout' => form => {csrf_token => $signed_in})
  ->status_is(303)->header_is(Location => '/login');
$t->get_ok('/account')->status_is(302);

$member->get_ok('/login')->status_is(200);
$member->post_ok('/login' => form => {
    username => 'member', password => $ENV{HEIMDALL_MEMBER_PASSWORD}, csrf_token => csrf($member),
  })->status_is(303);
$member->get_ok('/account')->status_is(200)->content_like(qr/Hello, member/);
$member->get_ok('/admin')->status_is(403);

done_testing;
