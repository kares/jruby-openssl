source 'https://gem.coop'

# Specify your gem's dependencies in the gemspec
gemspec if defined? JRUBY_VERSION

gem "rake", require: false

group :test do
  gem 'base64', require: false
  gem 'mocha', '~> 1.4', '< 2.0'
  gem 'test-unit'
end
