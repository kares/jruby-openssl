# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))
require 'tmpdir'

class TestConfig < TestCase

  def test_include_file_and_directory
    Dir.mktmpdir("ossl-config-include") do |dir|
      Dir.mkdir(File.join(dir, "child"))
      File.write(File.join(dir, "child", "a.conf"), "[sec-a]\na = 123\n")
      File.write(File.join(dir, "child", "b.cnf"),  "[sec-b]\nb = 456\n")
      File.write(File.join(dir, "frag.conf"), "[sec-main]\nmain = 789\n")
      main = <<~EOF
        [default]
        file-main = unnamed
        .include #{File.join(dir, 'frag.conf')}
        .include #{File.join(dir, 'child')}
      EOF
      c = OpenSSL::Config.parse(main)
      assert_equal(["default", "sec-a", "sec-b", "sec-main"], c.sections.sort)
      assert_equal({ "a" => "123" }, c["sec-a"])
      assert_equal({ "b" => "456" }, c["sec-b"])
      assert_equal({ "main" => "789" }, c["sec-main"])
    end
  end

  # a self- or mutually-referencing .include must raise instead of looping forever
  def test_include_cycle_raises
    Dir.mktmpdir("ossl-config-cycle") do |dir|
      self_cnf = File.join(dir, "self.cnf")
      File.write(self_cnf, "[default]\nx = 1\n.include #{self_cnf}\n")
      assert_raise(OpenSSL::ConfigError) { OpenSSL::Config.new(self_cnf) }

      a = File.join(dir, "a.cnf"); b = File.join(dir, "b.cnf")
      File.write(a, ".include #{b}\n")
      File.write(b, ".include #{a}\n")
      assert_raise(OpenSSL::ConfigError) { OpenSSL::Config.new(a) }
    end
  end

end
