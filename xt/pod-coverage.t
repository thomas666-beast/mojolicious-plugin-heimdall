use Mojo::Base -strict;
use Test::More;
use Test::Pod::Coverage;

my @modules = qw(
  Mojolicious::Plugin::Heimdall
  Mojolicious::Plugin::Heimdall::Facade
  Mojolicious::Plugin::Heimdall::Password
  Mojolicious::Plugin::Heimdall::Random
  Mojolicious::Plugin::Heimdall::Crypto
  Mojolicious::Plugin::Heimdall::JWT
  Mojolicious::Plugin::Heimdall::Auth
);

for my $mod (@modules) {
  pod_coverage_ok($mod, { also_private => [qr/^_/] }, "$mod POD coverage");
}

done_testing;
