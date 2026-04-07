# frozen_string_literal: true

require 'jopenssl/load'

module OpenSSL
  autoload :Config, 'openssl/config' unless const_defined?(:Config, false)
  autoload :ConfigError, 'openssl/config' unless const_defined?(:ConfigError, false)
  autoload :PKCS12, 'openssl/pkcs12'
end

=begin
= Info
  'OpenSSL for Ruby 2' project
  Copyright (C) 2002  Michal Rokos <m.rokos@sh.cvut.cz>
  All rights reserved.

= Licence
  This program is licensed under the same licence as Ruby.
  (See the file 'COPYING'.)
=end

require 'openssl/bn'
require 'openssl/cipher'
require 'openssl/digest'
require 'openssl/hmac'
require 'openssl/pkcs5'
require 'openssl/pkey'
require 'openssl/ssl'
require 'openssl/x509'

module OpenSSL
  # :call-seq:
  #    OpenSSL.secure_compare(string, string) -> true or false
  #
  # Constant time memory comparison. Inputs are hashed using SHA-256 to mask
  # the length of the secret. Returns +true+ if the strings are identical,
  # +false+ otherwise.
  #
  # This method is expensive due to the SHA-256 hashing. In most cases, where
  # the input lengths are known to be equal or are not sensitive,
  # OpenSSL.fixed_length_secure_compare should be used instead.
  def self.secure_compare(a, b)
    hashed_a = OpenSSL::Digest.digest('SHA256', a)
    hashed_b = OpenSSL::Digest.digest('SHA256', b)
    OpenSSL.fixed_length_secure_compare(hashed_a, hashed_b) && a == b
  end
end
