package org.jruby.ext.openssl;

/**
 * FIPS-mode latch helper usable from any test package - unlike {@link SecurityHelperTest}
 * it has no non-FIPS BC dependencies, so it also compiles on a BC-FIPS-only classpath.
 */
public abstract class FipsTestSupport {

    public static void setFipsMode(final boolean fipsMode, final boolean reset) {
        if (reset) SecurityHelper.FIPS_MODE.set(0); // reset flag
        SecurityHelper.setFipsMode(fipsMode);
    }

}
