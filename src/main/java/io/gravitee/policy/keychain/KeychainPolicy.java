/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.keychain;

import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.naming.PartialResultException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.keychain.configuration.KeychainPolicyConfiguration;
import io.gravitee.policy.keychain.model.keychainservice.PartnerKeyDto;
import io.gravitee.policy.keychain.model.keychainservice.PartnerKeyDtoResponse;

/**
 * @author Diogo Aihara (diogo at gr1d.io)
 * @author gr1d.io team
 */
public class KeychainPolicy {

    private final KeychainPolicyConfiguration keychainPolicyConfiguration;
    private final static String CONTEXT_NAME_API_KEY = "gravitee.attribute.api-key";
    private final static String ENV_URL_SERVICE = "gr1d-keychain-url";
    private final static String CREDENTIAL_USER_KEY = "user";
    private final static String CREDENTIAL_PASS_KEY = "pass";

    private static final Logger LOGGER = LoggerFactory.getLogger(KeychainPolicy.class);

    public KeychainPolicy(KeychainPolicyConfiguration keychainPolicyConfiguration) {
        this.keychainPolicyConfiguration = keychainPolicyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        String url = null;
        PartnerKeyDtoResponse responseData = null;
        
        // this.showRequestInfo(request, executionContext);

        String api = executionContext.getAttribute(ExecutionContext.ATTR_API).toString();
        String application = executionContext.getAttribute(ExecutionContext.ATTR_APPLICATION).toString();
        String client = executionContext.getAttribute(ExecutionContext.ATTR_USER_ID).toString();
        String plan = executionContext.getAttribute(ExecutionContext.ATTR_PLAN).toString();
        String serviceUrl = System.getenv(KeychainPolicy.ENV_URL_SERVICE);
        url = String.format("%s/%s/%s/%s/%s", serviceUrl, client, application, plan, api);
        // KeychainPolicy.LOGGER.warn(String.format("*** URL: %s", url));
        
//        gr1d-keychain-urlRestTemplate gr1d-keychain-url = new RestTemplate();
//        responseData = restTemplate.getForObject(url, PartnerKeyDtoResponse.class);
        // KeychainPolicy.LOGGER.warn(String.format("*** Response: %s", responseData.toString()));
        
        this.processKeychainResponse(responseData, request);

        policyChain.doNext(request, response);
    }

    private void showRequestInfo(Request request, ExecutionContext executionContext) {
        HttpHeaders headers = request.headers();
        String debugMessage = "*** HEADERS\n";
        for (String key : headers.keySet()) {
            String value = headers.getFirst(key);
            debugMessage += String.format("- %s: %s\n", key, value);
        }
        KeychainPolicy.LOGGER.warn(debugMessage);
        
        debugMessage = "*** Exection Context Attributes\n";
        List<String> executionContextAttributeNames = Collections.list(executionContext.getAttributeNames());
        for(String key : executionContextAttributeNames) {
            debugMessage += String.format("- %s: %s\n", key, executionContext.getAttribute(key));
        }
        KeychainPolicy.LOGGER.warn(debugMessage);
        

        debugMessage = String.format(
            "*** Variáveis:\n- ATTR_API: %s\n- ATTR_USER_ID: %s\n- ATTR_PLAN: %s\n- ATTR_APPLICATION: %s\n- X-GRAVITEE-API-KEY: %s",
            executionContext.getAttribute(ExecutionContext.ATTR_API),
            executionContext.getAttribute(ExecutionContext.ATTR_USER_ID),
            executionContext.getAttribute(ExecutionContext.ATTR_PLAN),
            executionContext.getAttribute(ExecutionContext.ATTR_APPLICATION),
            executionContext.getAttribute(CONTEXT_NAME_API_KEY)
            );
        KeychainPolicy.LOGGER.warn(debugMessage);

    }

    private void processKeychainResponse(PartnerKeyDtoResponse responseData, Request request) {
        PartnerKeyDto partnerKeyDto = responseData.getData();
        Map<String, String> credentials = partnerKeyDto.getCredentials();
        HttpHeaders headers = request.headers();

        switch (partnerKeyDto.getAuthType()) {
            case none:
                break;
            case user_pass:            
                // se for user_pass, o usuário vem no credentialBase e o pass vem no credentialExtra
                String userPass = String.format("%s:%s", credentials.get(KeychainPolicy.CREDENTIAL_USER_KEY), credentials.get(KeychainPolicy.CREDENTIAL_PASS_KEY));
                String encodedHeader = Base64.getEncoder().encodeToString(userPass.getBytes());
                headers.add("Authorization", String.format("Basic %s", encodedHeader));
                break;
            default:
                this.insertHeaders(credentials, headers);
                break;
            
        }
    }

    private void insertHeaders(Map<String, String> credentials, HttpHeaders headers) {
        for(Map.Entry<String, String> entry : credentials.entrySet()) {
            headers.add(entry.getKey(), entry.getValue());
        }
    }
}
