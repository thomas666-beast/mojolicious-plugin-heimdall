use Mojo::Base -strict;
use Test::More;
use Mojolicious;
use Mojolicious::Plugin::Heimdall;

my $class = 'Mojolicious::Plugin::Heimdall';

ok(defined $Mojolicious::Plugin::Heimdall::VERSION, 'VERSION defined');
ok($class->can('register'), 'has register method');
ok($class->isa('Mojolicious::Plugin'), 'inherits from Mojolicious::Plugin');

done_testing;
