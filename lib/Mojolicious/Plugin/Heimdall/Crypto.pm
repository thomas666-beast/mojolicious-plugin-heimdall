package Mojolicious::Plugin::Heimdall::Crypto;
use Mojo::Base -base, -signatures;

use Crypt::PK::RSA;
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::PRNG qw(random_bytes);
use MIME::Base64 qw(encode_base64 decode_base64);

sub rsa_generate ($self, $bits = 2048) {
  my $pk = Crypt::PK::RSA->new;
  $pk->generate_key($bits / 8, 65537);
  return {
    private_pem => $pk->export_key_pem('private'),
    public_pem  => $pk->export_key_pem('public'),
  };
}

sub rsa_encrypt ($self, $plain, $public_pem) {
  my $pk = Crypt::PK::RSA->new(\$public_pem);
  return encode_base64($pk->encrypt($plain), '');
}

sub rsa_decrypt ($self, $cipher_b64, $private_pem) {
  my $pk = Crypt::PK::RSA->new(\$private_pem);
  return $pk->decrypt(decode_base64($cipher_b64));
}

sub aes_gcm_encrypt ($self, $plain, $key, $aad = '') {
  my $iv = random_bytes(12);
  my ($ct, $tag) = gcm_encrypt_authenticate('AES', $key, $iv, $aad, $plain);
  return {
    iv         => encode_base64($iv,    ''),
    ciphertext => encode_base64($ct,    ''),
    tag        => encode_base64($tag,   ''),
  };
}

sub aes_gcm_decrypt ($self, $blob, $key, $aad = '') {
  my $iv  = decode_base64($blob->{iv});
  my $ct  = decode_base64($blob->{ciphertext});
  my $tag = decode_base64($blob->{tag});
  my $pt  = gcm_decrypt_verify('AES', $key, $iv, $aad, $ct, $tag);
  return defined $pt ? $pt : undef;
}

1;
__END__

=head1 NAME

Mojolicious::Plugin::Heimdall::Crypto - RSA and AES-GCM encryption

=head1 SYNOPSIS

  my $crypto = $c->heimdall->crypto;

  # RSA
  my $keys = $crypto->rsa_generate(2048);
  my $ct   = $crypto->rsa_encrypt($plain, $keys->{public_pem});
  my $pt   = $crypto->rsa_decrypt($ct, $keys->{private_pem});

  # AES-GCM (authenticated)
  my $key  = random_bytes(32);   # 256-bit key, generate once and store securely
  my $blob = $crypto->aes_gcm_encrypt($plain, $key, 'user:42');
  my $pt   = $crypto->aes_gcm_decrypt($blob, $key, 'user:42');

=head1 DESCRIPTION

Wraps L<CryptX> for asymmetric and symmetric encryption.
RSA uses OAEP padding (CryptX default) [citation:11].
AES-GCM uses the one-shot interface, which performs constant-time tag
verification [citation:2][citation:4].

Requires CryptX >= 0.088_001 due to CVE-2026-13758 and CVE-2026-41564.

=cut
