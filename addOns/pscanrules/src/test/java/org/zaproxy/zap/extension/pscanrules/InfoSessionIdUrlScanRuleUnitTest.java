/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.httpsessions.HttpSessionToken;
import org.zaproxy.zap.extension.httpsessions.HttpSessionsParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class InfoSessionIdUrlScanRuleUnitTest extends PassiveScannerTest<InfoSessionIdUrlScanRule> {

    private HttpMessage msg;
    private static final String BODY = "Some text in the response, doesn't matter.\nLine 2\n";

    @Override
    protected InfoSessionIdUrlScanRule createScanner() {

        InfoSessionIdUrlScanRule scanner = new InfoSessionIdUrlScanRule();
        setUpHttpSessionsParam();
        return scanner;
    }

    protected HttpMessage createHttpMessageWithRespBody(String responseBody)
            throws HttpMalformedHeaderException, URIException {

        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.setResponseBody(responseBody);
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/plain\r\n"
                        + "Content-Length: "
                        + responseBody.length()
                        + "\r\n");
        return msg;
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(6)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_SESS_04_SESS_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_SESS_04_SESS_EXPOSED.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_SESS_04_SESS_EXPOSED.getValue())));
    }

    @Test
    void shouldReturnExpectedExampleAlerts() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(3)));

        Alert alert1 = alerts.get(0);
        assertThat(alert1.getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alert1.getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
        assertThat(alert1.getParam(), is(equalTo("jsessionid")));
        assertThat(alert1.getEvidence(), is(equalTo("1A530637289A03B07199A44E8D531427")));
        assertThat(alert1.getCweId(), is(equalTo(598)));
        assertThat(alert1.getAlertRef(), is(equalTo(rule.getPluginId() + "-1")));

        Alert alert2 = alerts.get(1);
        assertThat(alert2.getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alert2.getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
        assertThat(
                alert2.getEvidence(), is(equalTo("jsessionid=1A530637289A03B07199A44E8D531427")));
        assertThat(alert1.getCweId(), is(equalTo(598)));
        assertThat(alert2.getAlertRef(), is(equalTo(rule.getPluginId() + "-2")));

        Alert alert3 = alerts.get(2);
        assertThat(alert3.getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alert3.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alert3.getEvidence(), is(equalTo("www.example.org")));
        assertThat(alert1.getCweId(), is(equalTo(598)));
        assertThat(alert3.getAlertRef(), is(equalTo(rule.getPluginId() + "-3")));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    @Test
    void noAlertOnIDSmallerThanMinimum() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://example.com/foo?jsessionid=1A53063";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void containsSessionIdAsUrlParameter() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://example.com/foo?jsessionid=1A530637289A03B07199A44E8D531427";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    void containsSessionIdAsUrlParameterInHTTPS()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com/foo?jsessionid=1A530637289A03B07199A44E8D531427";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    void noSessionIdInURL() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com/";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void noSessionIDAsUrlParameter() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com/session/foo?session=false";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void containsSessionIdAsUrlParameterInHTTPSOnCustomPort()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com:4443/foo?jsessionid=1a530637289b03x07199de8D531427";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When

        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    void containsJsessionIdInUrlPathBeforeParams()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://tld.gtld/fred;JSESSIONID=asdfasdfasdf1234?foo=bar";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    void alertsWithoutJSessionidInOptions() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://tld.gtld/fred;JSESSIONID=asdfasdfasdf1234?foo=bar";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // Set the session options to blank and verify it still reports the presence of
        // the jsessionid in the URL path before the parameters.
        OptionsParam options = Model.getSingleton().getOptionsParam();
        HttpSessionsParam sessionOptions = options.getParamSet(HttpSessionsParam.class);
        sessionOptions.setDefaultTokens(Collections.emptyList());

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    void containsCFIDAsUrlParameter() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://example.com/foo?CFiD=1A530637289A03B07199A44E8D531427";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    @Disabled(value = "Scanner does not look for session IDs in the response embedded in HREFs")
    void containsSessionIdInResponseHREFParams() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://tld.gtld/fred?foo=bar";
        String body =
                "<html>\n<body>\n<h2>HTML Links</h2>\n"
                        + "<p><a href=\"https://www.example.org/html/?jsessionid=1A530637289A03B07199A44E8D531427\">Testing ZAP</a>"
                        + "</p>\n"
                        + "</body>\n</html>";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    @Disabled(
            value =
                    "Scanner does not look for session IDs in the response embedded in HREFs before the parameters")
    void containsCFIDInResponseHREFBeforeParams()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://tld.gtld/fred?foo=bar";
        String body =
                "<html>\n<body>\n<h2>HTML Links</h2>\n"
                        + "<p><a href=\"https://www.example.org/html/;CFID=asdfasdfasdf1234?foo=bar\">Testing ZAP</a>"
                        + "</p>\n"
                        + "</body>\n</html>";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    void detectExposureTo3rdPartyInHREF() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com/foo?jsessionid=1A530637289A03B07199A44E8D531427";
        String body =
                "<html>\n<body>\n<h2>HTML Links</h2>\n"
                        + "<p><a href=\"https://www.example.org/html/\">Testing ZAP</a>"
                        + "</p>\n"
                        + "</body>\n</html>";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(2, alertsRaised.size());
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(2 - 1).getRisk());
    }

    @Test
    void detectExposureTo3rdPartyInHREFwCustomPort()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com:8888/foo?jsessionid=1A530637289A03B07199A44E8D531427";
        String body =
                "<html>\n<body>\n<h2>HTML Links</h2>\n"
                        + "<p><a href=\"https://www.example.org/html/\">Testing ZAP</a>"
                        + "</p>\n"
                        + "</body>\n</html>";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(2, alertsRaised.size());
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(2 - 1).getRisk());
    }

    @Test
    void detectExposureTo3rdPartyUnquotedHREF() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com/foo?jsessionid=1A530637289A03B07199A44E8D531427";
        String body =
                "<html>\n<body>\n<h2>HTML Links</h2>\n"
                        + "<p><a href=https://www.example.org/html/hello>Testing ZAP</a>"
                        + "</p>\n"
                        + "</body>\n</html>";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(2, alertsRaised.size());
    }

    @Test
    void detectExposureTo3rdPartyInSRC() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com/foo?jsessionid=1A530637289A03B07199A44E8D531427";
        String body =
                "<html>\n<body>\n<h2>HTML Links</h2>\n"
                        + "<p><a href=\"default.jsp\">\n"
                        + " <img src=\"https://www.example.org/images/smiley.gif\" alt=\"HTML tutorial\" "
                        + "style=\"width:42px;height:42px;border:0;\">\n</a>"
                        + "</p>\n"
                        + "</body>\n</html>";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertEquals(2, alertsRaised.size());
    }

    @Test
    void ignoreExposureToSelf() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com/foo?jsessionid=1A530637289A03B07199A44E8D531427";
        String body =
                "<html>\n<body>\n<h2>HTML Links</h2>\n"
                        + "<p><a href=\"https://example.com/html/\">Testing ZAP</a>"
                        + "</p>\n"
                        + "</body>\n</html>";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then:
        // Passing means it detects the session ID in the URL (alert #1), but since the
        // origin of the href in the body is the same as the URL, it should not raise a
        // 2nd alert.
        assertEquals(1, alertsRaised.size());
    }

    @Test
    void ignoreExposureToSelfRelativeLink() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com/foo?jsessionid=1A530637289A03B07199A44E8D531427";
        String body =
                "<html>\n<body>\n<h2>HTML Links</h2>\n"
                        + "<p><a href=\"default.jsp\">\n"
                        + " <img src=\"smiley.gif\" alt=\"HTML tutorial\" "
                        + "style=\"width:42px;height:42px;border:0;\">\n</a>"
                        + "</p>\n"
                        + "</body>\n</html>";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then:
        // Passing means it detects the session ID in the URL (alert #1), but since the
        // href in the body is self relative, it should not raise a 2nd alert.
        assertEquals(1, alertsRaised.size());
    }

    @Test
    void ignoreExposureToBookmark() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com/foo?jsessionid=1A530637289A03B07199A44E8D531427";
        String body =
                "<html>\n<body>\n<h2>HTML Links</h2>\n"
                        + "<h2 id=\"C4\">Chapter 4</h2>"
                        + "<p><a href=\"#C4\">Jump to Chapter 4</a></p>\n"
                        + "</body>\n</html>";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        scanHttpResponseReceive(msg);

        // Then:
        // Passing means it detects the session ID in the URL (alert #1), but since the
        // href in the body is also self relative, it should not raise a 2nd alert.
        assertEquals(1, alertsRaised.size());
    }

    private static void setUpHttpSessionsParam() {
        OptionsParam options = Model.getSingleton().getOptionsParam();
        options.load(new ZapXmlConfiguration());
        HttpSessionsParam httpSessions = new HttpSessionsParam();
        options.addParamSet(httpSessions);
        httpSessions.setDefaultTokens(
                Arrays.asList(new HttpSessionToken("jsessionid"), new HttpSessionToken("cfid")));
    }
}
