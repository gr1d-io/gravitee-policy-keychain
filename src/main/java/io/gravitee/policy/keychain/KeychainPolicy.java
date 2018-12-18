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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.Base64;


import javax.naming.PartialResultException;
import javax.net.ssl.HttpsURLConnection;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.policy.api.PolicyResult;
import org.json.JSONArray;
import org.json.JSONObject;
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
 * @author Alexandre Tolstenko (tolstenko at gr1d.io)
 * @author gr1d.io team
 */
public class KeychainPolicy {

    private final KeychainPolicyConfiguration keychainPolicyConfiguration;

    private static final Logger LOGGER = LoggerFactory.getLogger(KeychainPolicy.class);
    private static final String METHOD = "method";

    public KeychainPolicy(KeychainPolicyConfiguration keychainPolicyConfiguration) {
        this.keychainPolicyConfiguration = keychainPolicyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        String url;
        //this.showRequestInfo(request, executionContext);

        KeychainPolicy.LOGGER.warn("preprocess" );

        try {
            if(processRequest(request,executionContext, policyChain))
                policyChain.doNext(request, response);
        } catch (Exception e) {
            // in case it fails not so gracefully
            KeychainPolicy.LOGGER.error(e.getMessage());
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.INTERNAL_SERVER_ERROR_500, e.getMessage()));
        }
    }

    // TODO: Tolsta: this is not optimized, neither well done. I spent lots of time to make this work, so I did it as fast as I could.
    public boolean processRequest(Request req, ExecutionContext executionContext, PolicyChain policyChain) throws IOException {
        String api = executionContext.getAttribute(ExecutionContext.ATTR_API).toString();
        String application = executionContext.getAttribute(ExecutionContext.ATTR_APPLICATION).toString();
        String client = executionContext.getAttribute(ExecutionContext.ATTR_USER_ID).toString();
        String url = "https://keychain.dev.gr1d.io/api/gravitee/" + client + "/" + application + "/" + api;

        KeychainPolicy.LOGGER.warn("keychainurl: " + url);

        URL obj = new URL(url);
        HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
        con.setRequestMethod("GET");

        BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();

        while ((inputLine = in.readLine()) != null)
            response.append(inputLine);
        in.close();

        String responseString = response.toString();

        KeychainPolicy.LOGGER.warn("response: " + responseString);

        JSONObject jsonObj = new JSONObject(responseString);
        JSONArray apiData = jsonObj.getJSONArray("apis");
        JSONArray errors = jsonObj.getJSONArray("errors");
        String status = jsonObj.getString("status");

        // check for errors
        if(errors.length()!=0)
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.INTERNAL_SERVER_ERROR_500, errors.toString()));
        // check if user is enabled
        else if(!status.equals("enabled"))
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.PAYMENT_REQUIRED_402, "USER DISABLED: " + status));
        // check if there is content to chain
        else if(apiData.length()==0)
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.INTERNAL_SERVER_ERROR_500,"No keychain found for this APP & API."));
        // set keychain data
        else {
            executionContext.setAttribute("keychain", apiData.toString());
            return true;
        }

        return false;
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
            executionContext.getAttribute(ExecutionContext.ATTR_APPLICATION)
            );
        KeychainPolicy.LOGGER.warn(debugMessage);

        String attributes="";
        for (Enumeration<String> enumeration = executionContext.getAttributeNames(); enumeration.hasMoreElements(); )
            attributes += enumeration.nextElement() + " ";

        KeychainPolicy.LOGGER.debug(attributes);
    }

    private void processKeychainResponse(PartnerKeyDtoResponse responseData, Request request) {
        PartnerKeyDto partnerKeyDto = responseData.getData();
        Map<String, String> credentials = partnerKeyDto.getCredentials();
        HttpHeaders headers = request.headers();

//        switch (partnerKeyDto.getAuthType()) {
//            case none:
//                break;
//            case user_pass:
//                // se for user_pass, o usuário vem no credentialBase e o pass vem no credentialExtra
//                String userPass = String.format("%s:%s", credentials.get(KeychainPolicy.CREDENTIAL_USER_KEY), credentials.get(KeychainPolicy.CREDENTIAL_PASS_KEY));
//                String encodedHeader = Base64.getEncoder().encodeToString(userPass.getBytes());
//                headers.add("Authorization", String.format("Basic %s", encodedHeader));
//                break;
//            default:
//                this.insertHeaders(credentials, headers);
//                break;
//
//        }
    }

    private void insertHeaders(Map<String, String> credentials, HttpHeaders headers) {
        for(Map.Entry<String, String> entry : credentials.entrySet()) {
            headers.add(entry.getKey(), entry.getValue());
        }
    }
}
