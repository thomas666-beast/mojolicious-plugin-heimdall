use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Mojolicious::Plugin::Heimdall',
    VERSION_FROM     => 'lib/Mojolicious/Plugin/Heimdall.pm',
    ABSTRACT_FROM    => 'lib/Mojolicious/Plugin/Heimdall.pm',
    AUTHOR           => 'Thomas <selfworker112@mailfence.com>',
    LICENSE          => 'artistic_2',
    MIN_PERL_VERSION => '5.026',

    PREREQ_PM => {
        'Mojolicious'                => '9.48',
        'Crypt::Passphrase'          => '0.023',
        'Crypt::Passphrase::Argon2'  => 0,
        'Crypt::Passphrase::Bcrypt'  => 0,
        'Crypt::URandom::Token'      => '0.005',
        'CryptX'                     => '0.091',
        'Crypt::JWT'                 => '0.038',
    },

    TEST_REQUIRES => {
        'Test::More'          => '1.302',
        'Test::Mojo'          => 0,
        'Test::Pod'           => '1.52',
        'Test::Pod::Coverage' => '1.10',
    },

    META_MERGE => {
        resources => {
            repository => 'https://github.com/thomas666-beast/mojolicious-plugin-heimdall',
            bugtracker => 'https://github.com/thomas666-beast/mojolicious-plugin-heimdall/issues',
        },
    },
);
