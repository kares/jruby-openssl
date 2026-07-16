# JRuby-OpenSSL

[JRuby-OpenSSL](https://github.com/jruby/jruby-openssl) is an add-on gem for
[JRuby](https://www.jruby.org/) that emulates the Ruby OpenSSL native library.

Under the hood it uses the [Bouncy Castle Crypto APIs](https://www.bouncycastle.org/java.html).

Each jruby-openssl gem release includes the Bouncy Castle library (BC Provider and
PKIX/CMS/EAC/PKCS/OCSP/TSP/OPENSSL jars), usually the latest available version.

Please report bugs and incompatibilities (preferably with test-cases) to either
the JRuby [mailing list][1] or the [bug tracker][2].

## Compatibility

| JRuby-OpenSSL | JRuby compat | JVM compat | supported BC |
|---------------|:------------:|-----------:|-------------:|
| ~>0.12.x      | 9.1.x-9.3.x  |  Java 8-15 |    1.65-1.68 |
| ~>0.13.x      | 9.1.x-9.4.x  |  Java 8-17 |    1.68-1.69 |
| ~>0.14.x      | 9.1.x-9.4.x  |  Java 8-21 |    1.71-1.74 |
| ~>0.15.x      | 9.2.x-10.0.x |  Java 8-25 |    1.78-1.83 |
| ~>0.16.x      | 9.3.x-10.0.x |  Java 8-25 |    1.83-1.85 |

For later versions check jruby-openssl gem spec's `jar` requirements.

## Security

JRuby-OpenSSL is an essential part of [JRuby](https://www.jruby.org/), please report security vulnerabilities to
`security@jruby.org` as detailed on JRuby's [security page](https://www.jruby.org/security) or using [GitHub][0].

Please note that most OpenSSL vulnerabilities do not affect JRuby since it's not using
any of OpenSSL's C code, only Ruby parts (*.rb) are the same as in MRI's OpenSSL library.

## FIPS

A FIPS 140-3 build, **jruby-openssl-fips** (separate gem), is available on request. 
It emulates the same Ruby `OpenSSL` API on top of the NIST-validated Bouncy Castle FIPS module (BC-FJA) 
instead of the regular Bouncy Castle jars, for deployments that need a validated cryptographic module. 
Ships separately (under GPL 3.0) - reach out to `self+jruby-openssl@kares.org` if you're interested.

NOTE: unlike C OpenSSL, `OpenSSL.fips_mode` cannot be changed at runtime, the flag reports which 
gem variant is activated (`true` under the FIPS gem, `false` otherwise).

## Supported configuration

Most runtime knobs are Java system properties. 
Under JRuby you pass them as `-J-D...` flags, e.g. `JRUBY_OPTS='-J-Djruby.openssl.debug=true'`.

### Runtime / JVM properties

| Property | Default | Effect |
|----------|---------|--------|
| `jruby.openssl.load.jars` | `true` | If set to `false`, `lib/jopenssl/load.rb` skips auto-loading the bundled BouncyCastle jars — handy when the provider jars are already supplied on the JVM classpath. |
| `jruby.openssl.debug` | `false` | Turns on internal debug logging and stack traces from the Java extension; the same effect as setting `OpenSSL.debug = true` at runtime. |
| `jruby.openssl.warn` | follows JRuby's warning mode (`runtime.warningsEnabled()`) | Enables or disables warnings from the extension. Set `false` to stay quiet regardless of `-w`. |
| `jruby.openssl.log.logger` | default stdout/stderr logger | Selects the internal logger implementation. Set it to `JUL` to route logs through `java.util.logging`. |
| `jruby.openssl.log.silence` | `true` | Silences a few noisy BC / BCJSSE JUL loggers by default. Set `false` to leave their levels untouched. |
| `jruby.openssl.provider.register` | follows FIPS mode (normally not registered) | Whether the BC JCE provider is globally registered via `Security.addProvider(...)`. When unset it registers only if a FIPS provider is in play; otherwise the provider is handed to `Cipher.getInstance(...)` directly, without global registration. |
| `jruby.openssl.provider.ssl` | `BCJSSE` | Selects the SSL provider. `BCJSSE`, `bcjsse`, `BC`, `bc`, or `true` all mean BCJSSE; an empty string or `false` disables it and falls back to the platform JSSE provider. |
| `jruby.openssl.ssl.error_wait_nonblock.backtrace` | falls back to `jruby.errno.backtrace` (which defaults to `false`) | Whether `SSLErrorWaitReadable` / `SSLErrorWaitWritable` carry backtraces on non-blocking I/O paths. |
| `jruby.openssl.x509.lookup.cache` | disabled | Caching for X.509 lookup results. `true` turns on a soft cache; an integer such as `8` gives a bounded strong/soft cache of that size; unset or `false` disables it. |

### Environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `SSL_CERT_FILE` | platform / packaged default CA file | Overrides the default certificate bundle used for X.509 default-path loading. If it ends in `.crt`, `.cer`, or `.pem` it's read as a PEM bundle; otherwise jruby-openssl treats it as a Java CA store path. |
| `SSL_CERT_DIR` | platform / packaged default CA directory | Overrides the default certificate directory list for X.509 default-path loading. Separate multiple directories with the platform path separator. |
| `OPENSSL_ALLOW_PROXY_CERTS` | unset / disabled | When set to anything other than `false`, proxy certificates are allowed during certificate chain validation. |

### Other supported customizations

- `OpenSSL.debug = true` gives you the same internal debug logging as `-Djruby.openssl.debug=true`
- when `jruby.openssl.warn` is unset, JRuby's own warning mode (`ruby -w`) decides whether warnings show
- `OpenSSL::Config` can look up variables from the process environment through the `ENV` section, matching the upstream Ruby OpenSSL config parser

## Testing

    rake jar # creates pom.xml and generates jopenssl.jar under lib
    rake test

This runs the Ruby test suite against the default JRuby version. The Java (JUnit)
tests run via Maven, optionally against a specific JRuby version:

    ./mvnw test -Djruby.versions=10.0.6.0

For running integration tests the gem will be installed first and the same
tests run for each supported Bouncy Castle version (see [listing][3]):

    ./mvnw verify -P test-9.4.14.0,test-10.0.6.0

NOTE: you can pick any JRuby version which is on [Maven Central][4] or on [ci.jruby][5]

## License

(c) 2009-2026 JRuby distributed under EPL 1.0 / GPL 2.0 / LGPL 2.1

[0]: https://github.com/jruby/jruby-openssl/security
[1]: https://github.com/jruby/jruby/wiki/MailingLists
[2]: https://github.com/jruby/jruby-openssl/issues/new
[3]: https://github.com/jruby/jruby-openssl/tree/master/integration
[4]: https://repo1.maven.org/maven2/org/jruby/
[5]: https://www.jruby.org/nightly
