package org.jruby.ext.openssl.util;

import java.io.IOException;
import java.util.HashSet;
import java.util.function.Function;

import org.jruby.Ruby;
import org.jruby.RubyBasicObject;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

public abstract class RubySupport {

    // error/exception factory helpers

    public static RaiseException newIOError(Ruby runtime, IOException e) {
        return newIOError(runtime, e.getMessage(), e);
    }

    public static RaiseException newIOError(Ruby runtime, String msg) {
        return new RaiseException(runtime, runtime.getIOError(), msg, true);
    }

    public static RaiseException newIOError(Ruby runtime, String msg, Exception e) {
        RaiseException ex = newIOError(runtime, msg);
        ex.initCause(e);
        return ex;
    }

    public static RaiseException newRuntimeError(Ruby runtime, Exception e) {
        return newRuntimeError(runtime, e.getMessage(), e);
    }

    public static RaiseException newRuntimeError(Ruby runtime, String msg) {
        return new RaiseException(runtime, runtime.getRuntimeError(), msg, true);
    }

    public static RaiseException newRuntimeError(Ruby runtime, String msg, Exception e) {
        RaiseException ex = newRuntimeError(runtime, msg);
        ex.initCause(e);
        return ex;
    }

    public static RaiseException newArgumentError(Ruby runtime, Exception e) {
        return newError(runtime, runtime.getArgumentError(), e);
    }

    public static RaiseException newErrorWithoutTrace(Ruby runtime, RubyClass errorClass, String message) {
        final IRubyObject backtrace = runtime.newEmptyArray();
        return new RaiseException(runtime, errorClass, message, backtrace, false);
    }

    public static RaiseException newError(Ruby runtime, RubyClass errorClass, String message, boolean nativeException) {
        return new RaiseException(runtime, errorClass, message, nativeException);
    }

    public static RaiseException newError(Ruby runtime, RubyClass errorClass, Throwable e) {
        return newError(runtime, errorClass, e.getMessage(), e);
    }

    public static RaiseException newError(Ruby runtime, RubyClass errorClass, String msg) {
        return newError(runtime, errorClass, msg, true);
    }

    public static RaiseException newError(Ruby runtime, RubyClass errorClass, String msg, Throwable e) {
        RaiseException ex = newError(runtime, errorClass, msg);
        ex.initCause(e);
        return ex;
    }

    public static <T extends Throwable> RaiseException newError(Function<T, RaiseException> errorFunction, T e) {
        RaiseException ex = errorFunction.apply(e);
        ex.initCause(e);
        return ex;
    }

    public static RaiseException newSecurityError(Ruby runtime, Throwable e) {
        return newSecurityError(runtime, e.getMessage(), e);
    }

    public static RaiseException newSecurityError(Ruby runtime, String msg, Throwable e) {
        RaiseException ex = new RaiseException(runtime, runtime.getSecurityError(), msg, true);
        ex.initCause(e);
        return ex;
    }

    public static CharSequence callerTraceAt(final ThreadContext context, final int level) {
        final IRubyObject caller0 = context.runtime.getKernel().callMethod(
                "caller",
                context.runtime.newFixnum(level),
                context.runtime.newFixnum(1)
        );
        if (caller0.isNil()) return null;
        final IRubyObject first = caller0.convertToArray().eltInternal(0);
        return first instanceof RubyString ? (RubyString) first : first.asString();
    }

    // extract **kwargs helpers (borrowed from JRuby's ArgsUtil)

    public static IRubyObject[] extractKeywordArgs(final ThreadContext context, RubyHash options, String... validKeys) {
        return extractKeywordArgs(context, options, validKeys, 0);
    }

    public static IRubyObject[] extractKeywordArgs(final ThreadContext context, RubyHash options, String[] validKeys, int offset) {
        final IRubyObject[] ret = new IRubyObject[offset + validKeys.length];

        final HashSet<RubySymbol> validKeySet = new HashSet<>(ret.length);

        for (int i = 0; i < validKeys.length; i++) {
            final String key = validKeys[i];
            RubySymbol keySym = context.runtime.newSymbol(key);
            IRubyObject val = options.fastARef(keySym);
            ret[offset + i] = val != null ? val : RubyBasicObject.UNDEF;
            validKeySet.add(keySym);
        }

        options.visitAll(new RubyHash.Visitor() {
            public void visit(IRubyObject key, IRubyObject value) {
                if (!validKeySet.contains(key)) {
                    throw context.runtime.newArgumentError("unknown keyword: " + key);
                }
            }
        });

        return ret;
    }

    public static String extractStringOpt(ThreadContext context, IRubyObject opts, String key) {
        return extractStringOpt(context, opts, key, false);
    }

    public static String extractStringOpt(ThreadContext context, IRubyObject opts,
                                          String key, boolean tryStringKey) {
        final IRubyObject val = extractOpt(context, opts, key, tryStringKey);
        return val == null ? null : val.convertToString().asJavaString();
    }

    public static RubyString extractRubyStringOpt(ThreadContext context, IRubyObject opts,
                                                  String key, boolean tryStringKey) {
        final IRubyObject val = extractOpt(context, opts, key, tryStringKey);
        return val == null ? null : val.convertToString();
    }

    public static int extractIntOpt(ThreadContext context, IRubyObject opts,
                                    String key, int defaultVal, boolean tryStringKey) {
        if (!(opts instanceof RubyHash)) return defaultVal;
        RubyHash hash = (RubyHash) opts;
        IRubyObject val = hash.fastARef(context.runtime.newSymbol(key));
        if (val == null && tryStringKey) val = hash.fastARef(context.runtime.newString(key));
        if (val == null || val.isNil()) return defaultVal;
        return RubyNumeric.fix2int(val);
    }

    public static IRubyObject extractOpt(ThreadContext context, IRubyObject opts,
                                         String key, boolean tryStringKey) {
        if (!(opts instanceof RubyHash)) return null;
        RubyHash hash = (RubyHash) opts;
        IRubyObject val = hash.fastARef(context.runtime.newSymbol(key));
        if (val == null && tryStringKey) val = hash.fastARef(context.runtime.newString(key));
        if (val == null || val.isNil()) return null;
        return val;
    }
}
