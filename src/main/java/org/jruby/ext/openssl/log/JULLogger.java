package org.jruby.ext.openssl.log;

import java.util.logging.Level;

import org.jruby.Ruby;
import org.jruby.ext.openssl.OpenSSL;
import org.jruby.ext.openssl.util.RubySupport;
import org.jruby.runtime.ThreadContext;

final class JULLogger implements Logger {

    private final java.util.logging.Logger logger;

    JULLogger(final String name) {
        this.logger = java.util.logging.Logger.getLogger(name);
    }

    @Override
    public boolean isDebug(final Ruby runtime) {
        return OpenSSL.isDebug() && logger.isLoggable(Level.FINE);
    }

    private boolean isInfo() {
        return logger.isLoggable(Level.INFO);
    }

    private boolean isWarn() {
        return OpenSSL.isWarn() && logger.isLoggable(Level.WARNING);
    }

    @Override
    public void debug(final Ruby runtime, final CharSequence msg) {
        if (!isDebug(runtime)) return;

        logger.log(Level.FINE, msgWithPrefix(msg, false));
    }

    @Override
    public void debug(final Ruby runtime, final CharSequence msg, final Throwable ex) {
        if (!isDebug(runtime)) return;

        logger.log(Level.FINE, msgWithPrefix(msg, true) + ex);
    }

    @Override
    public void debugStack(final Ruby runtime, final CharSequence msg, final Throwable ex) {
        if (!isDebug(runtime)) return;

        logger.log(Level.FINE, msgWithPrefix(msg, false), ex);
    }

    @Override
    public void info(final Ruby runtime, final CharSequence msg) {
        if (!isInfo()) return;

        logger.log(Level.INFO, msgWithPrefix(msg, false));
    }

    @Override
    public void warn(final Ruby runtime, final CharSequence msg) {
        if (!isWarn()) return;

        logger.log(Level.WARNING, msgWithPrefix(msg, false));
    }

    @Override
    public void warn(final Ruby runtime, final CharSequence msg, final Throwable ex) {
        if (!isWarn()) return;

        logger.log(Level.WARNING, msgWithPrefix(msg, true) + ex);
    }

    @Override
    public void warnWithCaller(final Ruby runtime, CharSequence msg) {
        if (!isWarn()) return;

        if (runtime != null) {
            final ThreadContext context = runtime.getCurrentContext();
            final CharSequence caller = RubySupport.callerTraceAt(context, 1);
            if (caller != null) msg = msgWithPrefix(msg, true) + '<' + caller + '>';
            else msg = msgWithPrefix(msg, false);
        }
        else {
            msg = msgWithPrefix(msg, false);
        }

        logger.log(Level.WARNING, msg.toString());
    }

    private static String msgWithPrefix(final CharSequence msg, final boolean space) {
        return (msg == null ? "" : msg) + (space ? " " : "");
    }
}