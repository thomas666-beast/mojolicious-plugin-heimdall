# Run the Heimdall login example

This local Mojolicious app demonstrates password verification, protected pages, an admin role check, and CSRF-protected sign-in and sign-out. The accounts are stored in memory. No database is needed.

## Start the app

Extract the release archive and enter the `Mojolicious-Plugin-Heimdall-0.002` directory. With Perl 5.26 or newer and `cpanm`, run these commands in Bash:

```bash
cpanm --installdeps .
export HEIMDALL_SESSION_SECRET="$(perl -MCrypt::PRNG=random_bytes -e 'print unpack("H*", random_bytes(32))')"
read -rsp 'Choose a local test password (at least 12 characters): ' HEIMDALL_ADMIN_PASSWORD
printf '\n'
HEIMDALL_ADMIN_PASSWORD="$HEIMDALL_ADMIN_PASSWORD" \
  perl -Ilib examples/heimdall_demo.pl daemon -l http://127.0.0.1:3000
```

Use a test-only password. The daemon runs in the foreground. Press `Ctrl+C` to stop it, then run `unset HEIMDALL_ADMIN_PASSWORD HEIMDALL_SESSION_SECRET` when you finish. To add a regular `member` user, pass a separate `HEIMDALL_MEMBER_PASSWORD` of at least 12 characters to the same command.

## Try it

1. Open [the admin page](http://127.0.0.1:3000/admin). You should be redirected to sign in.
2. Sign in as `admin` using the password you chose. You should return to the admin page.
3. Visit [your account](http://127.0.0.1:3000/account) and click **Sign out**. Visiting the admin page again should redirect you to sign in.
4. If you configured the optional `member` account, sign in as `member`. The account page works, but the admin page responds with HTTP 403.

Do not expose this example to the Internet. A real app needs a persistent user store, login throttling, HTTPS with secure cookies, and a way to revoke sessions if required. See the [deployment checklist](../docs/10-security-checklist.txt).
