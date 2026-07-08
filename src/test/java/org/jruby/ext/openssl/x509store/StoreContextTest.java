
package org.jruby.ext.openssl.x509store;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class StoreContextTest {

    @Test
    public void getExtraDataAtSizeReturnsNull() {
        final StoreContext ctx = new StoreContext(new Store());
        ctx.setApplicationData("app"); // sets idx 0, so extraData.size() == 1
        assertNull(ctx.getExtraData(StoreContext.ossl_ssl_ex_vcb_idx)); // idx 1 == size()
    }

    @Test
    public void getExtraDataRoundTrips() {
        final StoreContext ctx = new StoreContext(new Store());
        assertNull(ctx.getExtraData(0)); // no data yet
        ctx.setApplicationData("app");
        assertEquals("app", ctx.getExtraData(0));
        assertNull(ctx.getExtraData(3)); // beyond populated range
    }
}
