require 'rake/testtask'

# Runs the unit suite against security providers installed by the JVM:
# provider jars go on the system class-path and `java.security` registers them
# gem runs with `jruby.openssl.load.jars=false` and pulls in no jars of its own
#
# `providers` entries are { name:, class:, arg: } - `arg` configures the provider (e.g. "fips:BCFIPS")
# `jdk_providers` keeps the JDK's own providers (:all) or replaces them with the named ones
#
# caller must define a `file 'lib/jopenssl.jar'` task that builds its ext jar
def define_provider_test_task(name,
                              description:,
                              providers:,
                              jars:,
                              libs: nil,
                              root: File.expand_path('..', __dir__),
                              extra_ruby_opts: [],
                              jdk_providers: :all,
                              extra_security_properties: {},
                              clear_security_properties: false)
  test_java_security_file = File.join(root, 'target', "#{name}-java.security")
  replace = jdk_providers != :all

  task :"#{name}_setup" do
    properties = jdk_security_properties

    # { "security.provider.N" => value } -
    # JDK stops reading these at the first gap, indexes have to stay continuous
    provider_entries =
      properties.stringPropertyNames.select { |key| key.match?(/^security\.provider\.\d+$/) }
                .to_h { |key| [ key, properties.getProperty(key) ] }

    specs = providers.map { |provider| [ provider[:class], provider[:arg] ].compact.join(' ') }
    if replace
      provider_entries.each_key { |key| properties.remove(key) }
      specs += jdk_providers # named JDK providers kept, after ours
      offset = 0
    else
      offset = provider_entries.size # ours follow the JDK's built-in list
    end

    properties.clear if clear_security_properties
    # setProperty - Properties#merge maps to Hash#merge in JRuby (returns a copy)
    extra_security_properties.each { |key, value| properties.setProperty(key, value) }

    specs.each_with_index { |spec, i| properties.setProperty("security.provider.#{offset + i + 1}", spec) }

    mkdir_p File.dirname(test_java_security_file)
    out_stream = java.io.FileOutputStream.new(test_java_security_file)
    begin
      properties.store(out_stream, "security providers for `rake #{name}`")
    ensure
      out_stream.close
    end

    puts "\n------------------------ java.security ------------------------"
    puts File.read(test_java_security_file)
    puts "\n"

    classpath = jars.respond_to?(:call) ? jars.call : jars
    classpath += [ ENV['CLASSPATH'] ].compact.reject(&:empty?)
    ENV['CLASSPATH'] = classpath.join(File::PATH_SEPARATOR)
    ENV['JOSSL_TEST_PROVIDERS'] = providers.map { |provider| provider[:name] }.join(',')
  end

  provider_check = File.expand_path('../test/_provider-check.rb', File.dirname(__FILE__))

  Rake::TestTask.new(name) do |task|
    task.libs = libs.dup if libs
    task.libs << File.join(root, 'test')
    test_files = FileList[File.join(root, 'test/**/test*.rb')].to_a
    task.test_files = test_files.map { |path| path.sub("#{root}/test/", '') }
    task.verbose = false # using -v directly instead due issues with rake
    task.loader = :direct
    # '==' has the JDK use file as-is (it is the full config) instead of merging its own
    task.ruby_opts = [ "-J-Djava.security.properties==#{test_java_security_file}",
                       '-J-Djruby.openssl.load.jars=false',
                       '-v', '-rbundler/setup', "-r#{provider_check}" ] + extra_ruby_opts
  end
  task(name => [ 'lib/jopenssl.jar', :"#{name}_setup" ]).tap do |test_task|
    test_task.clear_comments # TestTask#define already put a generic description on it
    test_task.add_description(description)
  end
end

def jdk_security_properties
  conf = File.join(ENV_JAVA['java.home'], 'conf', 'security', 'java.security')
  File.exist?(conf) or fail "no java.security under #{ENV_JAVA['java.home']}"
  properties = java.util.Properties.new
  stream = java.io.FileInputStream.new(conf)
  begin
    properties.load(stream)
  ensure
    stream.close
  end
  properties
end
