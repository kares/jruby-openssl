require_relative 'version'

# NOTE: assuming user does pull in BC .jars from somewhere else on the class-path
if ENV_JAVA['jruby.openssl.load.jars'] != 'false' && java.security.Security.getProvider('BC').nil?
  bc_jars = begin
    require 'jar_dependencies' unless respond_to?(:require_jar, true)
    require_jar 'org.bouncycastle', 'bcprov-jdk18on', JOpenSSL.version('bcprov-jdk18on')
    require_jar 'org.bouncycastle', 'bcpkix-jdk18on', JOpenSSL.version('bcpkix-jdk18on')
    require_jar 'org.bouncycastle', 'bcutil-jdk18on', JOpenSSL.version('bcutil-jdk18on')
    require_jar 'org.bouncycastle', 'bctls-jdk18on',  JOpenSSL.version('bctls-jdk18on')
    true
  rescue LoadError, RuntimeError
    false
  end
  unless bc_jars
    vendor = File.expand_path('../../vendor', File.dirname(__FILE__))
    version = JOpenSSL.version('bcprov-jdk18on')
    load "#{vendor}/org/bouncycastle/bcprov-jdk18on/#{version}/bcprov-jdk18on-#{version}.jar"
    version = JOpenSSL.version('bcpkix-jdk18on')
    load "#{vendor}/org/bouncycastle/bcpkix-jdk18on/#{version}/bcpkix-jdk18on-#{version}.jar"
    version = JOpenSSL.version('bcutil-jdk18on')
    load "#{vendor}/org/bouncycastle/bcutil-jdk18on/#{version}/bcutil-jdk18on-#{version}.jar"
    version = JOpenSSL.version('bctls-jdk18on')
    load "#{vendor}/org/bouncycastle/bctls-jdk18on/#{version}/bctls-jdk18on-#{version}.jar"
  end
end

require 'jopenssl.jar'
JRuby::Util.load_ext('org.jruby.ext.openssl.OpenSSL')
