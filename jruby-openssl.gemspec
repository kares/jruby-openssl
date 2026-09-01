#-*- mode: ruby -*-

jopenssl = Module.new.tap do |mod|
  version_rb = File.expand_path('lib/jopenssl/version.rb', __dir__)
  mod.module_eval(File.read(version_rb), version_rb)
end.const_get(:JOpenSSL)


Gem::Specification.new do |s|
  s.name = 'jruby-openssl'

  s.version = jopenssl::VERSION
  # stays MAJOR.MINOR.PATCH - 4th segment is reserved for the fips variant
  if Gem::Version.new(s.version).release.segments.size != 3
    fail "jruby-openssl version must be MAJOR.MINOR.PATCH (got #{s.version})"
  end

  s.metadata['jopenssl_variant'] = 'main'
  s.metadata['source_code_uri'] = 'https://github.com/jruby/jruby-openssl'
  s.metadata['bug_tracker_uri'] = 'https://github.com/jruby/jruby-openssl/issues'
  s.metadata['rubygems_mfa_required'] = 'true'

  s.platform = 'java'
  s.authors = ['Karol Bucek', 'Ola Bini', 'JRuby contributors']
  s.email = 'jossl@kares.org'
  s.summary = "SSL/TLS and general-purpose cryptography for JRuby"
  s.description = "Ruby OpenSSL compatibility for JRuby, "  +
                  "based on Java JCA/JCE and Bouncy Castle libraries (does not depend on native OpenSSL)."
  s.licenses = [ 'EPL-1.0', 'GPL-2.0', 'LGPL-2.1' ]

  s.require_paths = ['lib']

  s.files = `git ls-files`.split("\n").
    select { |f| f =~ /^(lib)/ ||
                 f =~ /^(History|LICENSE|README|Rakefile|Mavenfile|pom.xml)/i } +
            ['lib/jopenssl.jar'] + Dir.glob('vendor/**/*.jar').sort

  s.required_ruby_version = '>= 2.5.0' # JRuby >= 9.2

  version_range = lambda { |artifact_id| "[1.80,#{jopenssl.version(artifact_id)}]" }
  s.requirements << "jar org.bouncycastle:bcprov-jdk18on, #{version_range.('bcprov-jdk18on')}" # Provider
  s.requirements << "jar org.bouncycastle:bcpkix-jdk18on, #{version_range.('bcpkix-jdk18on')}" # PKIX/CMS/EAC/PKCSOCSP/TSP/OPENSSL
  s.requirements << "jar org.bouncycastle:bctls-jdk18on,  #{version_range.('bctls-jdk18on')}"  # DTLS/TLS API/JSSE Provider
  s.requirements << "jar org.bouncycastle:bcutil-jdk18on, #{version_range.('bcutil-jdk18on')}"

end

# vim: syntax=Ruby
