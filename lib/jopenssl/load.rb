require_relative 'version'

# NOTE: assuming user does pull in BC .jars from somewhere else on the class-path
unless ENV_JAVA['jruby.openssl.load.jars'].eql?('false')
  version = JOpenSSL::BOUNCY_CASTLE_VERSION
  bc_jars = begin
    require 'jar_dependencies' unless respond_to?(:require_jar, true)
    require_jar 'org.bouncycastle', 'bcprov-jdk18on', version
    require_jar 'org.bouncycastle', 'bcpkix-jdk18on', version
    require_jar 'org.bouncycastle', 'bcutil-jdk18on', version
    require_jar 'org.bouncycastle', 'bctls-jdk18on',  version
    true
  rescue LoadError, RuntimeError
    false
  end
  unless bc_jars
    load "org/bouncycastle/bcprov-jdk18on/#{version}/bcprov-jdk18on-#{version}.jar"
    load "org/bouncycastle/bcpkix-jdk18on/#{version}/bcpkix-jdk18on-#{version}.jar"
    load "org/bouncycastle/bcutil-jdk18on/#{version}/bcutil-jdk18on-#{version}.jar"
    load "org/bouncycastle/bctls-jdk18on/#{version}/bctls-jdk18on-#{version}.jar"
  end
end

require 'jopenssl.jar'
JRuby::Util.load_ext('org.jruby.ext.openssl.OpenSSL')
