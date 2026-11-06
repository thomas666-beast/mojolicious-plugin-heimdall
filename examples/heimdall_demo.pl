#!/usr/bin/env perl
use Mojo::Base -strict, -signatures;
use Mojolicious::Lite -signatures;

plugin 'Heimdall', {
  auth => {
    session_key => 'uid',
    load_user   => sub ($app, $id) {
      return { id => $id, name => "user$id" };
    },
  },
};

# Simple in-memory user store
my %USERS = (
  alice => { id => 1, password_hash => undef },
  bob   => { id => 2, password_hash => undef },
);

# Pre-hash passwords on startup
app->hook(before_server_start => sub ($server, $app) {
  my $h = $app->heimdall;   # facade works without a controller
  for my $name (keys %USERS) {
    $USERS{$name}{password_hash} = $h->password->hash('secret123');
  }
});

get '/' => sub ($c) {
  my $h = $c->heimdall;
  my $rnd = $h->random;
  my $token = $rnd->token(24);
  my $user = $h->auth->current_user($c);

  $c->render(text => <<"END");
Heimdall demo
  session user : @{[ $user ? $user->{name} : '(none)' ]}
  random token : $token
  /login       : POST username=alice password=secret123
  /logout      : GET
  /jwt         : GET (issues HS256 JWT)
  /protected   : GET (requires login)
END
};

post '/login' => sub ($c) {
  my $name = $c->param('username') // '';
  my $pass = $c->param('password') // '';
  my $user = $USERS{$name};

  return $c->render(text => 'unknown user', status => 401)
    unless $user;
  return $c->render(text => 'bad password', status => 401)
    unless $c->heimdall->password->verify($pass, $user->{password_hash});

  $c->heimdall->auth->login($c, $user->{id});
  my $to = $c->heimdall->auth->return_to($c, '/');
  $c->redirect_to($to);
};

get '/logout' => sub ($c) {
  $c->heimdall->auth->logout($c);
  $c->redirect_to('/');
};

get '/jwt' => sub ($c) {
  my $secret = '0123456789abcdef0123456789abcdef';  # 32 bytes
  my $jwt = $c->heimdall->jwt;
  my $token = $jwt->encode({ sub => 1, iat => time }, $secret, 'HS256');
  my $claims = $jwt->decode($token, $secret, ['HS256']);
  $c->render(json => { token => $token, claims => $claims });
};

get '/protected' => sub ($c) {
  $c->heimdall->auth->require_login($c) or return;
  my $user = $c->heimdall->auth->current_user($c);
  $c->render(text => "Hello, $user->{name}");
};

app->start;
