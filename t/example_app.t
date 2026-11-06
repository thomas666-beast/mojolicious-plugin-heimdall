use Mojo::Base -strict;
use Test::More;
use Test::Mojo;
use Mojo::File qw(curfile);

my $script = curfile->dirname->sibling('examples', 'heimdall_demo.pl');
my $t = Test::Mojo->new($script);

# Root page
$t->get_ok('/')->status_is(200)->content_like(qr/Heimdall demo/);

# Protected without login -> redirect
$t->get_ok('/protected')->status_is(302);

# Login with wrong password
$t->post_ok('/login' => form => { username => 'alice', password => 'wrong' })
  ->status_is(401);

# Login correct
$t->post_ok('/login' => form => { username => 'alice', password => 'secret123' })
  ->status_is(302);

# Now protected works
$t->get_ok('/protected')->status_is(200)->content_like(qr/Hello, user1/);

# JWT endpoint
$t->get_ok('/jwt')->status_is(200)->json_has('/token')->json_is('/claims/sub' => 1);

# Logout
$t->get_ok('/logout')->status_is(302);
$t->get_ok('/protected')->status_is(302);

done_testing;
