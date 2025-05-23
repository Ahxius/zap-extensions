/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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

import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;

class MixedContentScanRuleUnitTest extends PassiveScannerTest<MixedContentScanRule> {

    @Override
    protected MixedContentScanRule createScanner() {
        return new MixedContentScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(6)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CRYP_03_CRYPTO_FAIL.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CRYP_03_CRYPTO_FAIL.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CRYP_03_CRYPTO_FAIL.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // THen
        assertThat(alerts.size(), is(equalTo(1)));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    @Test
    void shouldNotRaiseAlertIfHttpResource() {
        // Given
        String uri = "http://example.com/";
        HttpMessage msg =
                createHtmlResponse(uri, "<script src=\"https://example.com/script.js\"></script>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertIfHttpsResourceContainsNoMixedContent() {
        // Given
        String uri = "https://example.com/";
        HttpMessage msg =
                createHtmlResponse(uri, "<script src=\"https://example.com/script.js\"></script>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertIfHttpsResourceIsEmpty() {
        // Given
        String uri = "https://example.com/";
        HttpMessage msg = createHtmlResponse(uri, "");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertForNonHtmlContent() {
        // Given
        String uri = "https://example.com/script.js";
        HttpMessage msg =
                createResponse(
                        uri,
                        "text/javascript",
                        // Extracted from:
                        // https://raw.githubusercontent.com/angular/angular.js/master/src/ng/directive/attrs.js
                        "/** <img src=\"http://www.gravatar.com/avatar/{{hash}}\" alt=\"Description\"/> */");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertIfHttpsResourceContainsMixedContentInUnknownAttribute() {
        // Given
        String attribute = "unknown";
        String uri = "https://example.com/";
        HttpMessage msg =
                createHtmlResponse(uri, "<tag " + attribute + "=\"http://example.com/file\" />");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "src",
                "background",
                "classid",
                "codebase",
                "data",
                "icon",
                "usemap",
                "action",
                "formaction"
            })
    void shouldRaiseLowAlertIfHttpsResourceContainsMixedContentInKnownAttributes(String attribute) {
        // Given
        String uri = "https://example.com/";
        HttpMessage msg =
                createHtmlResponse(uri, "<tag " + attribute + "=\"http://example.com/file\" />");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is("http://example.com/file"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                is("tag=tag " + attribute + "=http://example.com/file\n"));
        assertThat(alertsRaised.get(0).getRisk(), is(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), is(Alert.CONFIDENCE_MEDIUM));
    }

    @ParameterizedTest
    @ValueSource(strings = {"action", "formaction"})
    void
            shouldNotRaiseAlertIfHttpsResourceContainsMixedContentInActionAndFormActionAttributesWhenInHighAlertThreshold(
                    String attribute) {
        // Given
        String uri = "https://example.com/";
        HttpMessage msg =
                createHtmlResponse(uri, "<tag " + attribute + "=\"http://example.com/file\" />");
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldRaiseMediumAlertIfHttpsResourceContainsMixedContentInScriptTag() {
        // Given
        String uri = "https://example.com/";
        HttpMessage msg =
                createHtmlResponse(uri, "<script src=\"http://example.com/script.js\"></script>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is("http://example.com/script.js"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                is("tag=script src=http://example.com/script.js\n"));
        assertThat(alertsRaised.get(0).getRisk(), is(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), is(Alert.CONFIDENCE_MEDIUM));
        // THC verify other info
    }

    @Test
    void shouldRaiseOneAlertForMultipleMixedContent() {
        // Given
        String uri = "https://example.com/";
        HttpMessage msg =
                createHtmlResponse(
                        uri,
                        "<script src=\"http://example.com/script.js\"></script>\n"
                                + "<img src=\"http://example.com/image.png\" />");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is("http://example.com/script.js"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                is(
                        "tag=script src=http://example.com/script.js\ntag=img src=http://example.com/image.png\n"));
    }

    private static HttpMessage createHtmlResponse(String uri, String respBody) {
        return createResponse(uri, "text/html", respBody);
    }

    private static HttpMessage createResponse(String uri, String respContentType, String respBody) {
        HttpMessage msg = new HttpMessage();
        try {
            msg.setRequestHeader("GET " + uri + " HTTP/1.1");
            msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
        } catch (HttpMalformedHeaderException e) {
            throw new RuntimeException(e);
        }

        if (StringUtils.isNotEmpty(respContentType)) {
            msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, respContentType);
        }

        msg.getResponseBody().setBody(respBody);

        return msg;
    }
}
