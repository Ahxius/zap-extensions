/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
/*
 * Integer Overflow an active scan rule
 * Copyright (C) 2015 Institute for Defense Analyses
 * @author Mark Rader based upon the example active scanner by psiinon
 */
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

public class IntegerOverflowScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanbeta.integeroverflow.";

    private static final int PLUGIN_ID = 30003;
    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION));
        alertTags.put(PolicyTag.API.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final Logger LOGGER = LogManager.getLogger(IntegerOverflowScanRule.class);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.C);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    private static String getError(char c) {
        return Constant.messages.getString(MESSAGE_PREFIX + "error" + c);
    }

    /*
     * This method is called by the active scanner for each GET and POST parameter for every page
     * @see org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.paros.network.HttpMessage, java.lang.String, java.lang.String)
     */
    @Override
    public void scan(HttpMessage msg, String param, String value) {

        if (checkStop() == true) {
            return;
        }
        if (isPage500(getBaseMsg())) // Check to see if the page was initially a 500
        {
            return; // Stop
        }

        String returnAttack = randomIntegerString(4); // The number of full length ints to send.
        if (attackVector(param, '1', returnAttack) == true) {
            return;
        }
        returnAttack = singleString(4, '0'); // The number of full length ints to send.
        if (attackVector(param, '2', returnAttack) == true) {
            return;
        }
        returnAttack = singleString(4, '1'); // The number of full length ints to send.
        if (attackVector(param, '3', returnAttack) == true) {
            return;
        }
        returnAttack = singleString(4, '9'); // The number of full length ints to send.
        if (attackVector(param, '4', returnAttack) == true) {
            return;
        }
        return;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        // The CWE id
        return 190;
    }

    @Override
    public int getWascId() {
        // The WASC ID
        return 3;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    private static String randomIntegerString(int length) {

        int numbercounter = 0;
        int character = 0;
        long charactercounter = 0;
        int maxcharacter = 11;
        StringBuilder sb1 = new StringBuilder(maxcharacter * length);
        while (numbercounter < length) {
            charactercounter = 0;
            while (charactercounter < maxcharacter) {
                character = 48 + (int) (Math.random() * 10);

                while (character > 57 && character < 48) {
                    character = 48 + (int) (Math.random() * 10);
                }

                charactercounter++;
                sb1.append((char) character);
            }
            numbercounter++;
        }
        return sb1.toString();
    }

    private static String singleString(int length, char c) // Single Character String
            {

        int numbercounter = 0;
        long charactercounter = 0;
        int maxcharacter = 11;
        StringBuilder sb1 = new StringBuilder(maxcharacter * length);
        while (numbercounter < length) {
            charactercounter = 0;
            while (charactercounter < maxcharacter) {
                charactercounter++;
                sb1.append(c);
            }
            numbercounter++;
        }
        return sb1.toString();
    }

    private boolean checkStop() {
        if (this.isStop()) { // Check if the user stopped things
            LOGGER.debug("Scan rule {} stopping.", getName());
            return true; // Stop!
        }
        return false;
    }

    private boolean attackVector(String param, char type, String returnAttack) {
        if (checkStop() == true) {
            return true;
        }
        HttpMessage msg;
        msg = getNewMsg();
        setParameter(msg, param, returnAttack);
        try {
            sendAndReceive(msg);
            if (isPage500(msg)) {
                LOGGER.debug("Found Header");
                buildAlert(
                                getBaseMsg().getRequestHeader().getURI().toString(),
                                param,
                                returnAttack,
                                type,
                                msg.getResponseHeader().getPrimeHeader())
                        .setMessage(msg)
                        .raise();
                return true;
            }
        } catch (IOException e) {
            LOGGER.debug(e.getMessage(), e);
        }
        return false;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildAlert(
                                "https://example.com/?years=1",
                                "years",
                                "95697568703220167658153205694899573480013738",
                                '1',
                                "HTTP/1.1 500 Internal Server Error")
                        .build());
    }

    private AlertBuilder buildAlert(
            String url, String param, String attack, char type, String evidence) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setUri(url)
                .setParam(param)
                .setAttack(attack)
                .setOtherInfo(getError(type))
                .setEvidence(evidence);
    }
}
