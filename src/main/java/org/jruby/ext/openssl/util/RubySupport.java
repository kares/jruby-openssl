package org.jruby.ext.openssl.util;

import java.util.HashSet;

import org.jruby.RubyBasicObject;
import org.jruby.RubyHash;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

public abstract class RubySupport {

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
