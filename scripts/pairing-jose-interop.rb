#!/usr/bin/env ruby
# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'openssl'
require 'stringio'
require 'jose'

unless JOSE::VERSION == '1.2.0'
  abort "expected Ruby JOSE 1.2.0, got #{JOSE::VERSION}"
end

FIXTURE_DIR = File.expand_path('../docs/fixtures', __dir__)
JWS_HEADER_KEYS = %w[alg kid typ].sort.freeze
JWE_HEADER_KEYS = %w[
  alg enc kid cty connect-v connect-sid connect-gen connect-pid connect-tid
  connect-iat connect-exp connect-recipient-thumbprint epk
].sort.freeze
OFFER_KEYS = %w[
  protocol_version session_id generation provider_id transaction_id issued_at
  expires_at recipient_key_fingerprint ciphertext_digest ciphertext
].sort.freeze


def synthetic_key(scalar_hex)
  group = OpenSSL::PKey::EC::Group.new('prime256v1')
  scalar = OpenSSL::BN.new(scalar_hex, 16)
  point = group.generator.mul(scalar).to_octet_string(:uncompressed)
  encode = ->(bytes) { Base64.urlsafe_encode64(bytes, padding: false) }
  JOSE::JWK.from_map(
    'kty' => 'EC',
    'crv' => 'P-256',
    'x' => encode.call(point[1, 32]),
    'y' => encode.call(point[33, 32]),
    'd' => encode.call(scalar.to_s(2).rjust(32, "\0"))
  )
end


def decode_segment(segment)
  JSON.parse(Base64.urlsafe_decode64(segment))
end


def verify_fixture(path)
  fixture = JSON.parse(File.read(path))
  provider = synthetic_key(fixture.fetch('provider_private_scalar_hex'))
  device = synthetic_key(fixture.fetch('recipient_private_scalar_hex'))
  compact = fixture.fetch('signed_offer')
  jws_parts = compact.split('.', -1)
  raise 'JWS compact format required' unless jws_parts.length == 3

  jws_header = decode_segment(jws_parts.fetch(0))
  raise 'unexpected JWS header fields' unless jws_header.keys.sort == JWS_HEADER_KEYS
  raise 'unexpected JWS header' unless jws_header == {
    'alg' => 'ES256',
    'kid' => fixture.fetch('provider_key_id'),
    'typ' => 'application/librescoot-pairing-offer+jws'
  }

  verified, payload, = provider.to_public.verify(compact)
  raise 'JWS verification failed' unless verified
  offer = JSON.parse(payload)
  raise 'unexpected offer fields' unless offer.keys.sort == OFFER_KEYS
  raise 'fixture binding mismatch' unless fixture.fetch('binding').all? { |key, value| offer[key] == value }
  raise 'ciphertext digest mismatch' unless offer.fetch('ciphertext_digest') ==
    Base64.urlsafe_encode64(Digest::SHA256.digest(offer.fetch('ciphertext')), padding: false)

  jwe_parts = offer.fetch('ciphertext').split('.', -1)
  raise 'JWE compact format required' unless jwe_parts.length == 5
  jwe_header = decode_segment(jwe_parts.fetch(0))
  raise 'unexpected JWE header fields' unless jwe_header.keys.sort == JWE_HEADER_KEYS
  raise 'unexpected JWE algorithms or content type' unless jwe_header.values_at('alg', 'enc', 'kid', 'cty') == [
    'ECDH-ES+A256KW', 'A256GCM', 'device-p256-v1', 'application/librescoot-pairing-config+json'
  ]
  binding_headers = {
    'connect-v' => 'protocol_version',
    'connect-sid' => 'session_id',
    'connect-gen' => 'generation',
    'connect-pid' => 'provider_id',
    'connect-tid' => 'transaction_id',
    'connect-iat' => 'issued_at',
    'connect-exp' => 'expires_at',
    'connect-recipient-thumbprint' => 'recipient_key_fingerprint'
  }
  binding_headers.each do |header, field|
    raise "JWE #{header} binding mismatch" unless jwe_header.fetch(header) == fixture.fetch('binding').fetch(field)
  end

  plaintext, = device.block_decrypt(offer.fetch('ciphertext'))
  raise 'JWE decryption failed or plaintext changed' unless plaintext == fixture.fetch('plaintext')
  puts "verified Go/Ruby fixture: #{File.basename(path)}"
end

Dir.glob(File.join(FIXTURE_DIR, 'pairing-v1*.json')).sort.each do |fixture|
  verify_fixture(fixture)
end
