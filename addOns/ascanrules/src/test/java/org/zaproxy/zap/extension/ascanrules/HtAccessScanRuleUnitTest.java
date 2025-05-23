/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.AbstractAppFilePluginUnitTest;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link HtAccessScanRule}. */
class HtAccessScanRuleUnitTest extends AbstractAppFilePluginUnitTest<HtAccessScanRule> {

    private static final String URL = "/.htaccess";
    private static final String HTACCESS_BODY = "order allow,deny";

    private static final String DEFAULT_BODY =
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    + "<html><head></head><body>\n"
                    + "<h1>Error Log for testing</h1>\n"
                    + "<p>Blah blah blah.</p>\n"
                    + "</body></html>";

    @Override
    protected HtAccessScanRule createScanner() {
        return new HtAccessScanRule();
    }

    @BeforeEach
    void setup() {
        this.setBody(HTACCESS_BODY);
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionAscanRules());
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = ((HtAccessScanRule) rule).getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(94)));
        assertThat(wasc, is(equalTo(14)));
        assertThat(tags.size(), is(equalTo(5)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getValue())));
    }

    @Test
    void shouldTargetApache() throws Exception {
        // Given
        TechSet techSet = new TechSet(Tech.C, Tech.Apache, Tech.ASP);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetIfNotApache() throws Exception {
        // Given
        TechSet techSet = new TechSet(Tech.C, Tech.Db2, Tech.ASP);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldNotAlertIfNonHtaccessFileFoundStdThreshold() throws Exception {
        // Given
        nano.addHandler(new MiscOkResponse());
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfNonHtaccessFileFoundLowThreshold() throws Exception {
        // Given
        nano.addHandler(new MiscOkResponse());
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"application/json", "application/xml"})
    void shouldNotAlertIfResponseIsJsonOrXml(String contentType) throws Exception {
        // Given
        nano.addHandler(new MiscOkResponse(URL, contentType));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfResponseIsEmpty() throws Exception {
        // Given
        nano.addHandler(new MiscOkResponse(""));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfSingleDirective() throws Exception {
        // Given
        nano.addHandler(new MiscOkResponse(URL, "text/plain", "Options"));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfInvalidDirective() throws Exception {
        // Given
        nano.addHandler(new MiscOkResponse(URL, "text/plain", "filestore"));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertHtaccessContent() throws Exception {
        // Given
        nano.addHandler(
                new MiscOkResponse(
                        URL,
                        "text/plain",
                        "Options +Includes\n"
                                + "AddType text/html shtml\n"
                                + "AddHandler server-parsed shtml"));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldNotAlertHtaccessContentInImage() throws Exception {
        // Given
        nano.addHandler(
                new MiscOkResponse(
                        URL,
                        "image/png",
                        "Options +Includes\n"
                                + "AddType text/html shtml\n"
                                + "AddHandler server-parsed shtml"));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertHtmlTextContent() throws Exception {
        // Given
        nano.addHandler(new MiscOkResponse(URL, "text/plain", DEFAULT_BODY));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertTextNoCommonDirectivesContent() throws Exception {
        // Given
        nano.addHandler(
                new MiscOkResponse(
                        URL,
                        "text/plain",
                        "This is text with no common htaccess directives in it"));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertTextNoValidDirectivesContent() throws Exception {
        // Given
        nano.addHandler(
                new MiscOkResponse(
                        URL,
                        "text/plain",
                        "This is text with the common directives 'files' in it in an invalid location"));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldHaveExpectedExampleAlerts() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(2)));
        Alert alert = alerts.get(0);
        Alert authAlert = alerts.get(1);
        assertThat(alert.getName(), is(equalTo(".htaccess Information Leak")));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        assertThat(alert.getAlertRef(), is(equalTo("40032-1")));
        assertThat(authAlert.getName(), is(equalTo(".htaccess Information Leak")));
        assertThat(authAlert.getRisk(), is(equalTo(Alert.RISK_INFO)));
        assertThat(authAlert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        assertThat(authAlert.getAlertRef(), is(equalTo("40032-2")));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    private static class MiscOkResponse extends NanoServerHandler {

        String contentType = "text.html";
        String content = DEFAULT_BODY;

        public MiscOkResponse() {
            super(URL);
        }

        public MiscOkResponse(String content) {
            super(URL);
            this.content = content;
        }

        public MiscOkResponse(String path, String contentType) {
            super(path);
            this.contentType = contentType;
        }

        public MiscOkResponse(String path, String contentType, String content) {
            this(path, contentType);
            this.content = content;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return newFixedLengthResponse(Response.Status.OK, contentType, content);
        }
    }
}
