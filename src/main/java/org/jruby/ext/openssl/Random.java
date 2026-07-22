/***** BEGIN LICENSE BLOCK *****
 * Version: EPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Eclipse Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/epl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2006 Ola Bini <ola@ologix.com>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the EPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the EPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/
package org.jruby.ext.openssl;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.util.ExceptionUtil;
import org.jruby.ext.openssl.util.RubySupport;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.ext.openssl.log.Logger;
import org.jruby.util.ByteList;
import org.jruby.util.SafePropertyAccessor;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.ThreadLocalRandom;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class Random {

    private static final Logger LOG = Logger.getLogger(Random.class);

    // thread-local (default), shared, strong
    static final String HOLDER_TYPE = SafePropertyAccessor.getProperty("jruby.openssl.random", "");

    private static Holder createHolderImpl() {
        if (HOLDER_TYPE.equals("default") || HOLDER_TYPE.equals("thread-local")) {
            return new ThreadLocalHolder();
        }
        if (HOLDER_TYPE.equals("shared")) {
            return new SharedHolder();
        }
        if (HOLDER_TYPE.equals("strong")) {
            return new StrongHolder();
        }
        return new ThreadLocalHolder();
    }

    static abstract class Holder {

        abstract java.util.Random getPlainRandom();

        abstract java.security.SecureRandom getSecureRandom(ThreadContext context) throws NoSuchAlgorithmException;

        void seedSecureRandom(ThreadContext context, byte[] seed) throws NoSuchAlgorithmException {
            getSecureRandom(context).setSeed(seed);
        }

        void seedPlainRandom(long seed) {
            getPlainRandom().setSeed(seed);
        }

    }

    private static class SharedHolder extends Holder {

        private volatile java.util.Random plainRandom;
        private volatile java.security.SecureRandom secureRandom;

        java.util.Random getPlainRandom() {
            if (plainRandom == null) {
                synchronized(this) {
                    if (plainRandom == null) {
                        plainRandom = new java.util.Random();
                    }
                }
            }
            return plainRandom;
        }

        java.security.SecureRandom getSecureRandom(ThreadContext context) throws NoSuchAlgorithmException {
            if (secureRandom == null) {
                synchronized(this) {
                    if (secureRandom == null) {
                        secureRandom = SecurityHelper.getSecureRandom();
                    }
                }
            }
            return secureRandom;
        }

    }

    private static class ThreadLocalHolder extends Holder {

        private final ThreadLocal<SecureRandom> secureRandomLocal =
                ThreadLocal.withInitial(() -> {
                    try {
                        return SecurityHelper.getSecureRandom();
                    } catch (NoSuchAlgorithmException e) {
                        ExceptionUtil.throwException(e); return null;
                    }
                });

        @Override
        java.util.Random getPlainRandom() {
            return ThreadLocalRandom.current();
        }

        @Override
        void seedPlainRandom(long seed) {
            // NO-OP - UnsupportedOperationException
        }

        @Override
        java.security.SecureRandom getSecureRandom(ThreadContext context) throws NoSuchAlgorithmException {
            return secureRandomLocal.get();
        }
    }

    private static class StrongHolder extends Holder {

        @Override
        java.util.Random getPlainRandom() {
            return new java.util.Random();
        }

        @Override
        java.security.SecureRandom getSecureRandom(ThreadContext context) throws NoSuchAlgorithmException {
            return SecurityHelper.getSecureRandomStrong();
        }

        void seedSecureRandom(ThreadContext context, byte[] seed) {
            // NOOP - new instance returned for getSecureRandom
        }

        void seedPlainRandom(long seed) {
            // NOOP - new instance returned for getPlainRandom
        }

    }

    static void createRandom(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        final RubyModule Random = OpenSSL.defineModuleUnder("Random");

        Random.defineClassUnder("RandomError", OpenSSLError, OpenSSLError.getAllocator());

        Random.defineAnnotatedMethods(Random.class);

        Random.dataWrapStruct(createHolderImpl());
    }

    @JRubyMethod(meta = true)
    public static RubyString random_bytes(final ThreadContext context,
        final IRubyObject self, final IRubyObject arg) {
        return random_bytes(context, self, toInt(context.runtime, arg));
    }

    static RubyString random_bytes(final ThreadContext context, final int len) {
        final RubyModule Random = (RubyModule) context.runtime.getModule("OpenSSL").getConstantAt("Random");
        return generate(context, Random, len, true); // secure-random
    }

    private static RubyString random_bytes(final ThreadContext context,
        final IRubyObject self, final int len) {
        return generate(context, self, len, true); // secure-random
    }

    @JRubyMethod(meta = true)
    public static RubyString pseudo_bytes(final ThreadContext context,
        final IRubyObject self, final IRubyObject len) {
        // NOTE: CRuby's pseudo_bytes is an alias for random_bytes (both use RAND_bytes)
        return generate(context, self, toInt(context.runtime, len), true); // secure-random
    }

    private static int toInt(final Ruby runtime, final IRubyObject arg) {
        final long len = RubyNumeric.fix2long(arg);
        if ( len < 0 || len > Integer.MAX_VALUE ) {
            throw runtime.newArgumentError("negative string size (or size too big) " + len);
        }
        return (int) len;
    }

    private static RubyString generate(final ThreadContext context,
        final IRubyObject self, final int len, final boolean secure) {
        final Holder holder = retrieveHolder((RubyModule) self);
        final byte[] bytes = new byte[len];
        try {
            ( secure ? holder.getSecureRandom(context) : holder.getPlainRandom() ).nextBytes(bytes);
        }
        catch (NoSuchAlgorithmException e) {
            throw newRandomError(context.runtime, e.getMessage());
        }
        return RubyString.newString(context.runtime, new ByteList(bytes, false));
    }

    private static Holder retrieveHolder(final RubyModule Random) {
        return (Holder) Random.dataGetStruct();
    }

    private static RaiseException newRandomError(final Ruby runtime, final String message) {
        final RubyModule Random = (RubyModule) runtime.getModule("OpenSSL").getConstantAt("Random");
        return RubySupport.newError(runtime, (RubyClass) Random.getConstantAt("RandomError"), message);
    }

    @JRubyMethod(meta = true) // seed(str) -> str
    public static IRubyObject seed(final ThreadContext context,
        final IRubyObject self, IRubyObject str) {
        seedImpl(context, (RubyModule) self, str);
        return str;
    }

    private static void seedImpl(ThreadContext context, final RubyModule Random, final IRubyObject str) {
        final byte[] seed = str.asString().getBytes();
        final Holder holder = retrieveHolder(Random);

        try {
            holder.seedSecureRandom(context, seed); // seed supplements existing (secure) seeding mechanism
        }
        catch (NoSuchAlgorithmException e) {
            throw newRandomError(context.runtime, e.getMessage());
        }

        long s; int l = seed.length;
        if ( l >= 4 ) {
            s = (seed[0] << 24) | (seed[1] << 16) | (seed[2] << 8) | seed[3];
            if ( l >= 8 ) {
                s = s ^ ((seed[l-4] << 24) | (seed[l-3] << 16) | (seed[l-2] << 8) | seed[l-1]);
            }
            holder.seedPlainRandom(s);
        }
    }

    // true if the PRNG has been seeded with enough data, false otherwise
    @JRubyMethod(meta = true, name = "status?") // status? => true | false
    public static IRubyObject status_p(final ThreadContext context, final IRubyObject self) {
        return context.runtime.newBoolean(true);
    }

    @JRubyMethod(meta = true, name = { "random_add", "add" }) // random_add(str, entropy) -> self
    public static IRubyObject random_add(final ThreadContext context,
        final IRubyObject self, IRubyObject str, IRubyObject entropy) {
        seedImpl(context, (RubyModule) self, str); // simply ignoring _entropy_ hint
        return self;
    }

    // C-Ruby OpenSSL::Random API stubs :

    @JRubyMethod(meta = true) // load_random_file(filename)
    public static IRubyObject load_random_file(final ThreadContext context,
        final IRubyObject self, IRubyObject fname) {
        return context.runtime.getNil();
    }

    @JRubyMethod(meta = true) // write_random_file(filename) -> true
    public static IRubyObject write_random_file(final ThreadContext context,
        final IRubyObject self, IRubyObject fname) {
        return context.runtime.getNil();
    }

    @JRubyMethod(meta = true) // egd(filename) -> true
    public static IRubyObject egd(final ThreadContext context,
        final IRubyObject self, IRubyObject fname) {
        // no-op let the JVM security infrastructure to its internal seeding
        return context.runtime.getTrue();
    }

    @JRubyMethod(meta = true) // egd_bytes(filename, length) -> true
    public static IRubyObject egd_bytes(final ThreadContext context,
        final IRubyObject self, IRubyObject fname, IRubyObject len) {
        // no-op let the JVM security infrastructure to its internal seeding
        return context.runtime.getTrue();
    }

}
