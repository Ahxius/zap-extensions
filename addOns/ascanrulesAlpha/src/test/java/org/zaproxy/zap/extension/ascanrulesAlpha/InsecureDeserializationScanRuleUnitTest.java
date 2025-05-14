package org.zaproxy.zap.extension.ascanrulesAlpha;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.net.URL;
import java.net.URLConnection;
import java.net.InetAddress;
import org.junit.jupiter.api.Test;

class InsecureDeserializationScanRuleUnitTest extends ActiveScannerTest<InsecureDeserializationScanRule> {

    @Override
    protected InsecureDeserializationScanRule createScanner() {
        return new InsecureDeserializationScanRule();
    }

    // Commented due to generateSerializedPayload being a private method and not easily testable
    // @Test
    // void shouldGenerateSerializedPayloadSuccessfully() throws Exception {
    //     String oastUrl = "http://example.com";
    //     byte[] payload = createScanner().generateSerializedPayload(oastUrl);
    //     assertThat(payload, is(notNullValue()));
    //     assertThat(payload.length, is(greaterThan(0)));
    // }


    // SilentURLStreamHandler class tests
    @Test
    void shouldReturnNullForOpenConnection() throws Exception {
        InsecureDeserializationScanRule.SilentURLStreamHandler handler = new InsecureDeserializationScanRule.SilentURLStreamHandler();
        URL url = new URL("http://example.com");
        URLConnection connection = handler.openConnection(url);
        assertThat(connection, is(nullValue()));
    }

    @Test
    void shouldReturnNullForGetHostAddress() throws Exception {
        InsecureDeserializationScanRule.SilentURLStreamHandler handler = new InsecureDeserializationScanRule.SilentURLStreamHandler();
        URL url = new URL("http://example.com");
        InetAddress address = handler.getHostAddress(url);
        assertThat(address, is(nullValue()));
    }

}