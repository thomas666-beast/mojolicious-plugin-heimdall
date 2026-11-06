package Mojolicious::Plugin::Heimdall::Auth;
use Mojo::Base -base, -signatures;

has 'session_key';      # default 'user_id'
has 'load_user';        # coderef($app, $id) -> user object or undef

sub new ($class, %args) {
  my $self = $class->SUPER::new(%args);
  $self->session_key($args{session_key} // 'user_id');
  return $self;
}

sub login ($self, $c, $user_id) {
  $c->session->{ $self->session_key } = $user_id;
  return $c;
}

sub logout ($self, $c) {
  delete $c->session->{ $self->session_key };
  return $c;
}

sub current_user ($self, $c) {
  my $id = $c->session->{ $self->session_key };
  return undef unless defined $id;
  if (my $loader = $self->load_user) {
    return $loader->($c->app, $id);
  }
  return $id;
}

sub is_authenticated ($self, $c) {
  return defined $c->session->{ $self->session_key };
}

sub require_login ($self, $c) {
  return 1 if $self->is_authenticated($c);
  my $redirect = $c->req->url->to_abs->to_string;
  $c->session->{heimdall_return_to} = $redirect;
  $c->redirect_to('/login');
  return 0;
}

sub return_to ($self, $c, $default = '/') {
  my $to = delete $c->session->{heimdall_return_to} // $default;
  return $to;
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

Coderef C<< sub ($app, $id) { ... } >> returning a user object.

=head1 METHODS

=head2 new

  my $auth = Mojolicious::Plugin::Heimdall::Auth->new(%args);

Constructor. Accepts C<session_key> and C<load_user>.

=head2 login

  $auth->login($c, $user_id);

Store the user ID in the session.

=head2 logout

  $auth->logout($c);

Remove the user ID from the session.

=head2 current_user

  my $user = $auth->current_user($c);

Return the user object (via C<load_user>) or the raw ID if no callback is
configured. Returns C<undef> if not authenticated.

=head2 is_authenticated

  my $bool = $auth->is_authenticated($c);

True if a user ID is present in the session.

=head2 require_login

  my $ok = $auth->require_login($c);

If authenticated, returns true. Otherwise stores the current URL under
C<heimdall_return_to> and redirects to C</login>, returning false.

=head2 return_to

  my $url = $auth->return_to($c, $default);

Return and clear the stored return URL, falling back to C<$default>.

=head1 SEE ALSO

L<Mojolicious::Sessions>, L<Mojolicious::Plugin::Heimdall>.

=cut
