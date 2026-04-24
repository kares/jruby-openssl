package org.jruby.ext.openssl.log;

import org.jruby.Ruby;

public interface Logger {

    static Logger getLogger(final Class<?> type) {
        return LoggerFactory.getLogger(type.getName());
    }

    static Logger getLogger(final String name) {
        return LoggerFactory.getLogger(name);
    }

    boolean isDebug(Ruby runtime);

    default void debug(CharSequence msg) {
        debug(null, msg);
    }

    void debug(Ruby runtime, CharSequence msg);

    default void debug(CharSequence msg, Throwable ex) {
        debug(null, msg, ex);
    }

    void debug(Ruby runtime, CharSequence msg, Throwable t);

    default void debugStack(Throwable ex) {
        debugStack(null, null, ex);
    }

    default void debugStack(CharSequence msg, Throwable ex) {
        debugStack(null, msg, ex);
    }

    void debugStack(Ruby runtime, CharSequence msg, Throwable ex);

    default void info(CharSequence msg) {
        info(null, msg);
    }

    void info(Ruby runtime, CharSequence msg);

    default void warn(CharSequence msg) {
        warn(null, msg);
    }

    void warn(Ruby runtime, CharSequence msg);

    void warn(Ruby runtime, CharSequence msg, Throwable t);

    default void warnWithCaller(Ruby runtime, CharSequence msg) {
        warn(runtime, msg);
    }
}
