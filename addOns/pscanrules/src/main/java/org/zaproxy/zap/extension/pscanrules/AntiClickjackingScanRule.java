/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class AntiClickjackingScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.anticlickjacking.";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                                CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                                CommonAlertTag.WSTG_V42_CLNT_09_CLICKJACK));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final int PLUGIN_ID = 10020;
    boolean includedInCsp;

    private enum VulnType {
        XFO_MISSING(1),
        XFO_MULTIPLE_HEADERS(2),
        XFO_META(3),
        XFO_MALFORMED_SETTING(4);

        private final int ref;

        private VulnType(int ref) {
            this.ref = ref;
        }

        public int getRef() {
            return this.ref;
        }
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        boolean includeErrorsAndRedirects = false;

        if (AlertThreshold.LOW.equals(this.getAlertThreshold())) {
            includeErrorsAndRedirects = true;
        } else {
            if (!msg.getResponseHeader().isHtml()) {
                return;
            }
        }

        if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isText()) {
            int responseStatus = msg.getResponseHeader().getStatusCode();
            // If it's an error/redirect and we're not including them then just return without
            // alerting
            if (!includeErrorsAndRedirects
                    && (getHelper().isServerError(msg)
                            || getHelper().isClientError(msg)
                            || HttpStatusCode.isRedirection(responseStatus))) {
                return;
            }
            // CSP takes precedence
            includedInCsp = false;
            List<String> csp = msg.getResponseHeader().getHeaderValues("Content-Security-Policy");
            if (!csp.isEmpty() && csp.toString().contains("frame-ancestors")) {
                // We could do more parsing here, but that will be non trivial
                includedInCsp = true;
            }

            if (includedInCsp && !AlertThreshold.LOW.equals(this.getAlertThreshold())) {
                // No need to check the X-Frame-Options header
                return;
            }

            List<String> xFrameOption =
                    msg.getResponseHeader().getHeaderValues(HttpHeader.X_FRAME_OPTION);
            if (!xFrameOption.isEmpty()) {
                for (String xFrameOptionParam : xFrameOption) {
                    if (xFrameOptionParam.toLowerCase().indexOf("deny") < 0
                            && xFrameOptionParam.toLowerCase().indexOf("sameorigin") < 0) {
                        buildAlert(xFrameOptionParam, VulnType.XFO_MALFORMED_SETTING).raise();
                    }
                }
                if (xFrameOption.size() > 1) { // Multiple headers
                    buildAlert("", VulnType.XFO_MULTIPLE_HEADERS).raise();
                }
            } else {
                buildAlert("", VulnType.XFO_MISSING).raise();
            }

            String metaXFO = getMetaXFOEvidence(source);

            if (metaXFO != null) {
                // XFO found defined by META tag
                buildAlert(metaXFO, VulnType.XFO_META).raise();
            }
        }
    }

    private AlertBuilder buildAlert(String evidence, VulnType currentVT) {
        int risk = Alert.RISK_MEDIUM;
        String other = "";
        if (this.includedInCsp) {
            risk = Alert.RISK_LOW;
            other = Constant.messages.getString(MESSAGE_PREFIX + "incInCsp");
        }

        return newAlert()
                .setName(getAlertElement(currentVT, "name"))
                .setRisk(risk)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getAlertElement(currentVT, "desc"))
                .setParam(HttpHeader.X_FRAME_OPTION)
                .setOtherInfo(other)
                .setSolution(getAlertElement(currentVT, "soln"))
                .setReference(getAlertElement(currentVT, "refs"))
                .setEvidence(evidence)
                .setCweId(1021) // CWE-1021: Improper Restriction of Rendered UI Layers or Frames
                .setWascId(15) // WASC-15: Application Misconfiguration
                .setAlertRef(PLUGIN_ID + "-" + currentVT.getRef());
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    private static String getAlertElement(VulnType currentVT, String element) {
        switch (currentVT) {
            case XFO_MISSING:
                return Constant.messages.getString(MESSAGE_PREFIX + "missing." + element);
            case XFO_MULTIPLE_HEADERS:
                return Constant.messages.getString(MESSAGE_PREFIX + "multiple.header." + element);
            case XFO_META:
                return Constant.messages.getString(MESSAGE_PREFIX + "compliance.meta." + element);
            case XFO_MALFORMED_SETTING:
                return Constant.messages.getString(
                        MESSAGE_PREFIX + "compliance.malformed.setting." + element);
            default:
                return "";
        }
    }

    /**
     * Checks the source of the response for XFO being set via a META tag which is explicitly not
     * supported per the spec (rfc7034).
     *
     * @param source the source of the response to be analyzed.
     * @return returns a string if XFO was set via META (for use as alert evidence) otherwise return
     *     {@code null}.
     * @see <a href="https://tools.ietf.org/html/rfc7034#section-4">RFC 7034 Section 4</a>
     */
    private static String getMetaXFOEvidence(Source source) {
        List<Element> metaElements = source.getAllElements(HTMLElementName.META);
        String httpEquiv;

        if (metaElements != null) {
            for (Element metaElement : metaElements) {
                httpEquiv = metaElement.getAttributeValue("http-equiv");
                if (HttpHeader.X_FRAME_OPTION.equalsIgnoreCase(httpEquiv)) {
                    return metaElement.toString();
                }
            }
        }
        return null;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        for (VulnType vulnType : VulnType.values()) {
            alerts.add(buildAlert("", vulnType).build());
        }
        return alerts;
    }
}
