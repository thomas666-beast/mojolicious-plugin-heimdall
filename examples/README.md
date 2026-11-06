# Heimdall Example Application

Run:

    carton exec -- perl examples/heimdall_demo.pl daemon

Then open http://localhost:3000 and try:

- `POST /login` with `username=alice&password=secret123`
- `GET /protected` (redirects to / if not logged in)
- `GET /jwt` (issues and verifies an HS256 JWT)
- `GET /logout`

The example demonstrates every module of `Mojolicious::Plugin::Heimdall`.
