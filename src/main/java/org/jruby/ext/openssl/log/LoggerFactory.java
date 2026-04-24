package org.jruby.ext.openssl.log;

import java.util.function.Function;

abstract class LoggerFactory {

    static Function<String, Logger> factory = (name) -> new DefaultLogger(name);

    static Logger getLogger(final String name) {
        return factory.apply(name);
    }
}
