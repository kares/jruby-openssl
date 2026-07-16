open module org.jruby.ext.openssl {
    // org.jruby.dist is the JRuby runtime automatic-module name since 9.4.13
    requires org.jruby.dist;

    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.tls;
    requires org.bouncycastle.util; // asn1.cms/asn1.edec live in bcutil

    requires java.logging; // org.jruby.ext.openssl.log JULLogger

    exports org.jruby.ext.openssl;
    exports org.jruby.ext.openssl.log;
}