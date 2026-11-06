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

  # In your app startup
  $app->plugin('Heimdall', {
    auth => {
      session_key => 'user_id',
      load_user   => sub ($app, $id) {
        return $app->users->find($id);
      },
    },
  });

  # In a controller
  $c->heimdall->auth->login($c, $user->id);
  my $user = $c->heimdall->auth->current_user($c);
  $c->heimdall->auth->require_login($c) or return;
  $c->heimdall->auth->logout($c);

=head1 DESCRIPTION

Wraps L<Mojolicious::Sessions> to provide login/logout/current_user
helpers. Stores only the user id in the session; the user object is
loaded lazily via the C<load_user> coderef, so account changes are
picked up on the next request.

=cut
