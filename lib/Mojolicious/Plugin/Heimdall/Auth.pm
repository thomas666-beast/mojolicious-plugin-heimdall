package Mojolicious::Plugin::Heimdall::Auth;
use Mojo::Base -base, -signatures;
use Carp qw(croak);
use Scalar::Util qw(refaddr);

has 'session_key';      # default 'user_id'
has 'load_user';        # coderef($app, $id) -> user object or undef

sub new ($class, %args) {
  my $self = $class->SUPER::new(%args);
  $self->session_key($args{session_key} // 'user_id');
  return $self;
}

sub login ($self, $c, $user_id) {
  _check_secrets($c);
  croak 'Heimdall: login requires a nonempty scalar user ID'
    unless defined $user_id && !ref($user_id) && length($user_id);
  my $session = $c->session;
  delete $session->{csrf_token};
  delete $c->stash->{'heimdall.auth_user'}{refaddr($self)};
  $session->{ $self->session_key } = $user_id;
  return $c;
}

sub logout ($self, $c) {
  _check_secrets($c);
  my $session = $c->session;
  delete @{$session}{$self->session_key, 'csrf_token', 'heimdall_return_to'};
  delete $c->stash->{'heimdall.auth_user'}{refaddr($self)};
  return $c;
}

sub current_user ($self, $c) {
  _check_secrets($c);
  my $id = $c->session->{ $self->session_key };
  return undef unless defined $id && !ref($id) && length($id);
  if (my $loader = $self->load_user) {
    my $cache = $c->stash->{'heimdall.auth_user'} //= {};
    my $cached = $cache->{refaddr($self)};
    return $cached->[1] if $cached && $cached->[0] eq $id;
    my $user = $loader->($c->app, $id) || undef;
    $cache->{refaddr($self)} = [$id, $user];
    return $user;
  }
  return $id;
}

sub is_authenticated ($self, $c) {
  return defined $self->current_user($c);
}

sub require_login ($self, $c) {
  return 1 if $self->is_authenticated($c);
  my $session = $c->session;
  my $url = $c->req->url;
  my $path = $url->path->to_string;
  my $query = $url->query->to_string;
  delete @{$session}{$self->session_key, 'heimdall_return_to'};
  my $target = $path . (length($query) ? "?$query" : '');
  $session->{heimdall_return_to} = $target
    if ($c->req->method // '') =~ /\A(?:GET|HEAD)\z/ && _local_target($target);
  $c->redirect_to('/login');
  return 0;
}

sub return_to ($self, $c, $default = '/') {
  _check_secrets($c);
  my $to = delete $c->session->{heimdall_return_to};
  return $to if _local_target($to);
  return _local_target($default) ? $default : '/';
}

sub _local_target ($target) {
  return 0 if !defined($target) || ref($target) || length($target) > 1024;
  return 0 if $target =~ /[\\\x00-\x20\x7f#]/;
  return 0 unless $target =~ m{\A/(?!/|%2f|%5c)}i;
  my ($path) = split /\?/, $target, 2;
  return $path !~ /%(?:0[0-9a-f]|1[0-9a-f]|7f|5c)/i;
}

sub _check_secrets ($c) {
  my $app = $c->app;
  return unless $app->mode eq 'production';
  my $secrets = $app->secrets;
  croak 'Heimdall: configure explicit random session secrets (at least 32 bytes each)'
    unless ref($secrets) eq 'ARRAY' && @$secrets && !grep {
      !defined($_) || ref($_) || /[^\x00-\xff]/ || length($_) < 32 || $_ eq $app->moniker
    } @$secrets;
}

1;

__END__

=head1 NAME

Mojolicious::Plugin::Heimdall::Auth - Session-based authentication

=head1 SYNOPSIS

  $app->plugin('Heimdall', {
    auth => {
      session_key => 'uid',
      load_user   => sub ($app, $id) { $app->users->find($id) },
    },
  });

  $c->heimdall->auth->login($c, $user->id);
  my $user = $c->heimdall->auth->current_user($c);
  $c->heimdall->auth->logout($c);

=head1 DESCRIPTION

Session authentication on top of L<Mojolicious::Sessions>. Only the user ID
is stored in the session; the user object is loaded lazily via the
C<load_user> callback.

=head1 ATTRIBUTES

=head2 session_key

  my $key = $auth->session_key;

Session key holding the user ID. Default C<user_id>.

=head2 load_user

  my $cb = $auth->load_user;

Coderef C<< sub ($app, $id) { ... } >> returning a truthy user value
for an active account or C<undef> for a missing or disabled account.
The result is cached for the current request only.

=head1 METHODS

=head2 new

  my $auth = Mojolicious::Plugin::Heimdall::Auth->new(%args);

Constructor. Accepts C<session_key> and C<load_user>.

=head2 login

  $auth->login($c, $user_id);

Store a previously verified user ID and clear the pre-login CSRF token.
In production, session authentication requires explicit random signing
secrets set on the app. It cannot measure the entropy of a configured value.

=head2 logout

  $auth->logout($c);

Remove the user ID, return path and CSRF token from the browser session.
This cannot revoke copies of a previously issued client-side cookie.
Use a session store or a server-side revocation check when that is required.

=head2 current_user

  my $user = $auth->current_user($c);

Return the user object (via C<load_user>) or the raw ID if no callback is
configured. Returns C<undef> if not authenticated.

=head2 is_authenticated

  my $bool = $auth->is_authenticated($c);

True if C<current_user> resolves a user. Without a loader, an ID in the
signed session is enough for authentication, but not for authorization.

=head2 require_login

  my $ok = $auth->require_login($c);

If authenticated, returns true. Otherwise clears the stale user ID,
remembers a safe local GET or HEAD path, and redirects to C</login>,
returning false.

=head2 return_to

  my $url = $auth->return_to($c, $default);

Return and clear the stored local path, falling back to C<$default>
when it is local, or C</> otherwise.

=head1 SEE ALSO

L<Mojolicious::Sessions>, L<Mojolicious::Plugin::Heimdall>.

=cut
