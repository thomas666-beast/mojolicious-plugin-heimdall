requires 'perl', '5.026';
requires 'Mojolicious', '9.48';
requires 'Crypt::Passphrase', '0.023';
requires 'Crypt::Passphrase::Argon2', '0';
requires 'Crypt::Passphrase::Bcrypt', '0';
requires 'Crypt::URandom::Token', '0.005';
requires 'CryptX', '0.091';
requires 'Crypt::JWT', '0.038';

on 'test' => sub {
  requires 'Test::More', '1.302';
  requires 'Test::Pod', '1.52';
  requires 'Test::Pod::Coverage', '1.10';
};
