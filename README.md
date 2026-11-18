# Mojolicious::Plugin::Heimdall

Heimdall is a small security toolbox for Mojolicious: password hashing, secure random values, encryption, JWTs, and cookie-based authentication. Load it with `plugin 'Heimdall'` and use the helpers under `$c->heimdall`. Heimdall does not replace your user database, permission rules, or deployment controls.

## Install and run

Use Perl 5.26 or newer and `cpanm`. A compiler and `make` may be needed for the crypto dependencies. For the supplied release archive:

```sh
cpanm ./Mojolicious-Plugin-Heimdall-0.002.tar.gz
```

From a source checkout, install dependencies with `cpanm --installdeps .` and use `perl -Ilib` to run the example without installing Heimdall itself.

- [Run the complete login example](examples/README.md): sign in, visit a protected page, check the admin role, and sign out.
- [Use signed API access tokens](docs/06-jwt-jws.txt): create and verify tokens with expiration, issuer, audience, and subject.
- [Read the security checklist](docs/10-security-checklist.txt): review secrets, cookies, throttling, and revocation before deploying.
- [Browse the docs](docs/README.md): use each of the five tools independently.

## Upgrading from 0.001

- Heimdall now requires Mojolicious 9.48 or newer and CryptX 0.091 or newer.
- For session authentication in production, set `app->secrets` to independently generated random keys of at least 32 bytes each. This includes old keys still accepted for verification. Configure `Secure` cookies for HTTPS.
- If `load_user` is configured, return a user value only for active accounts. Returning `undef` now denies access even if the cookie still holds a user ID. Check roles separately.
- `return_to` accepts a local path, not an absolute URL. Older saved absolute URLs are discarded. Login and logout clear the previous CSRF token; render or fetch a new form after signing in.
- Existing low-level JWT helpers still work. Use `verify_access_token` for bearer credentials. The demo is shipped as an example, not installed on your `PATH`.

See [Mojolicious session configuration](https://metacpan.org/pod/Mojolicious::Sessions) and [JWT Best Current Practices](https://www.rfc-editor.org/info/rfc8725/) for background.
