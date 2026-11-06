requires 'perl', '5.026';
requires 'Mojolicious', '9.0';
requires 'Crypt::Passphrase', '0.023';
requires 'Crypt::Passphrase::Argon2', '0';
requires 'Crypt::Passphrase::Bcrypt', '0';
requires 'Crypt::URandom::Token', '0.005';
requires 'CryptX', '0.088_001';

on 'test' => sub {
  requires 'Test::More', '1.302';
};

on 'develop' => sub {
  requires 'Dist::Zilla';
  requires 'Test::Pod';
};
