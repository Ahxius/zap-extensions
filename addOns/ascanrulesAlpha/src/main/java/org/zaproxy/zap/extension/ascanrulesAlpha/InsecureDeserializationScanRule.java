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

import java.util.HashMap;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.addon.oast.ExtensionOast;

public class InsecureDeserializationScanRule extends AbstractAppParamPlugin implements CommonActiveScanRuleInfo {

    private static final int PLUGIN_ID = 90041; // unique ID, created by referencing the ZAP scan rule ID list

    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("cwe_502"); // cwe_502 matches insecure deserialization

    private static final Logger LOGGER = LogManager.getLogger(InsecureDeserializationScanRule.class); // creates a logger specific to this scan rule

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
        return Category.SERVER; // since insecure deserialization is a server-side vulnerability
    }

    // THIS SHOULD INCLUDE ANY LATER TECHNOLOGIES (i.e. .NET, Python, etc)
    // This isolates the scan rule to only run on certain frameworks, commented out for debugging
    // @Override
    // public boolean targets(TechSet technologies) {
    //     return technologies.includes(Tech.JAVA);
    // }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        try {
            ExtensionOast extOast = Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class); // creates a OAST extension for out-of-band testing
            if (extOast != null && extOast.getCallbackService() != null) { // checks if the object was properly instantiated
                HttpMessage newMsg = getNewMsg(); // retrieves the message object from the active scanner
                Alert alert = // alerts are used to visually display a vulnerability and suggested remediations
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM) // confidence that this is an actual vulnerability
                                .setMessage(newMsg) // provides context
                                .setSource(Alert.Source.ACTIVE) // attaches it to the active scan rules
                                .build();
                // makes it so the alert is called if the generated payload is triggered
                String callbackPayload = extOast.registerAlertAndGetPayloadForCallbackService(alert, InsecureDeserializationScanRule.class.getSimpleName());
                byte[] payload = generateSerializedPayload(callbackPayload);
                newMsg.setRequestBody(payload); // sets the request body to the generated payload
                sendAndReceive(newMsg); // sends the request to the server
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
        System.out.println("Generating payload for OAST payload: " + oastUrl); // for debugging
        Object payload = generateJavaObject(oastUrl);
        return payload.toString().getBytes(); // serializes the payload
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
    private Object generateJavaObject(String url) throws MalformedURLException{
        URLStreamHandler handler = new SilentURLStreamHandler(); // creates a URL stream handler that guarantees no network operations

        HashMap<URL, String> ht = new HashMap<URL, String>(); // creates a hash map (required for the attack) with a URL as both key and value (the value is stored as a string)
        URL u = new URL(null, url, handler);
        ht.put(u, url);

        try {
            Field field = u.getClass().getDeclaredField("hashCode");
            field.setAccessible(true);
            field.set(u, -1); // manually sets the hash code to -1 to prevent the URL object from being cached
                              // when the server receives the HashMap and sets the hash code to 0, it will create a DNS request to the key
        } catch (NoSuchFieldException | IllegalAccessException e) {
            LOGGER.warn("Could not set hashCode field on URL object.", e);
            return null;
        }

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