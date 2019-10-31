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

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyConfiguration;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.keychain.configuration.KeychainPolicyConfiguration;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;

/**
 * @author Diogo Aihara (diogo at gr1d.io)
 * @author Alexandre Tolstenko (tolstenko at gr1d.io)
 * @author gr1d.io team
 */
public class KeychainPolicy {

  private final KeychainPolicyConfiguration keychainPolicyConfiguration;

  private static final Logger LOGGER = LoggerFactory.getLogger(KeychainPolicy.class);
  private static final String KEYCHAIN_KEY = "keychain";
  private static final String APIS_KEY = "apis";
  private static final String ERRORS_KEY = "errors";
  private static final String STATUS_KEY = "status";
  private static final String DEFAULT_KEYCHAIN_URL = "https://keychain.gr1d.io";
  private static final String WHITESPACE = " ";
  private static final String ENCODED_WHITESPACE = "%20";

  public KeychainPolicy(PolicyConfiguration keychainPolicyConfiguration) {
    this.keychainPolicyConfiguration = (KeychainPolicyConfiguration) keychainPolicyConfiguration;
  }

  @OnRequest
  public void onRequest(Request request, Response response, ExecutionContext executionContext,
      PolicyChain policyChain) {
    String api = executionContext.getAttribute(ExecutionContext.ATTR_API).toString();
    String application =
        executionContext.getAttribute(ExecutionContext.ATTR_APPLICATION).toString();
    String client = executionContext.getAttribute(ExecutionContext.ATTR_USER_ID).toString();
    String keychainUrl = this.keychainPolicyConfiguration.getKeychainUrl();

    KeychainPolicy.LOGGER.warn("[Keychain] From Config: " + keychainUrl);

    if (keychainUrl == null || keychainUrl.isEmpty()) {
      keychainUrl = KeychainPolicy.DEFAULT_KEYCHAIN_URL;
    }
    String url = String.format("%s/api/gravitee/%s/%s/%s", keychainUrl, client, application, api);

    KeychainPolicy.LOGGER.warn("[Keychain] URL: " + url);

    try {
      Vertx vertx = Vertx.currentContext().owner();
      HttpClient httpClient = vertx.createHttpClient();

      httpClient.getAbs(url).handler(res -> {
        if (res.statusCode() < 500) {
          res.bodyHandler(new Handler<Buffer>() {
            @Override
            public void handle(Buffer buffer) {
              JSONObject jsonObj = new JSONObject(buffer.toString());
              Boolean hasEntry = !jsonObj.isNull(KeychainPolicy.STATUS_KEY);
              String status = !hasEntry ? "disabled" : jsonObj.getString(KeychainPolicy.STATUS_KEY);
              JSONArray errors = jsonObj.isNull(KeychainPolicy.STATUS_KEY) ? new JSONArray()
                  : jsonObj.getJSONArray(KeychainPolicy.ERRORS_KEY);
              JSONArray apis = jsonObj.isNull(KeychainPolicy.APIS_KEY) ? new JSONArray()
                  : jsonObj.getJSONArray(KeychainPolicy.APIS_KEY);

              // check for errors
              if (errors.length() != 0) {
                policyChain.failWith(PolicyResult.failure(HttpStatusCode.INTERNAL_SERVER_ERROR_500,
                    errors.toString()));
              }

              if (keychainPolicyConfiguration.getMandatory()) {

                // check if user is enabled
                if (!status.equals("enabled")) {
                  policyChain.failWith(PolicyResult.failure(HttpStatusCode.PAYMENT_REQUIRED_402,
                      "USER DISABLED: " + status));
                }
                // check if there is content to chain
                else if (apis.length() == 0) {
                  policyChain
                      .failWith(PolicyResult.failure(HttpStatusCode.INTERNAL_SERVER_ERROR_500,
                          "No keychain found for this APP & API."));
                }
                // set keychain data
                else {
                  KeychainPolicy.LOGGER.warn("[Keychain] setAttribute");
                  executionContext.setAttribute(KeychainPolicy.KEYCHAIN_KEY, apis.toString());
                  policyChain.doNext(request, response);
                }
              } else {
                // check if user is disabled, having an entry in keychain
                if (!status.equals("enabled") && hasEntry) {
                  policyChain.failWith(PolicyResult.failure(HttpStatusCode.PAYMENT_REQUIRED_402,
                      "USER DISABLED: " + status));
                }
                // set the default keychain data
                else {
                  KeychainPolicy.LOGGER.warn("[Keychain] default setAttribute");
                  StringBuilder format = new StringBuilder(String.format(
                      "[{\"_Gr1d_appId\": \"%s\", \"_Gr1d_apiId\": \"%s\", \"_Gr1d_method\": \"%s\"",
                      application, api, keychainPolicyConfiguration.getMethod().getName()));

                  if (keychainPolicyConfiguration.getAddParameters() != null) {
                    keychainPolicyConfiguration.getAddParameters().forEach(queryParameter -> {
                      if (queryParameter.getName() != null
                          && !queryParameter.getName().trim().isEmpty()) {
                        try {
                          String extValue =
                              (queryParameter.getValue() != null) ? queryParameter.getValue()
                                  : null;
                          // encode whitespace
                          String name;
                          if (queryParameter.getName().contains(WHITESPACE)) {
                            name =
                                queryParameter.getName().replaceAll(WHITESPACE, ENCODED_WHITESPACE);
                          } else {
                            name = queryParameter.getName();
                          }

                          if (extValue.contains(WHITESPACE)) {
                            extValue = extValue.replaceAll(WHITESPACE, ENCODED_WHITESPACE);
                          }

                          format.append(String.format(", \"%s\": \"%s\"", name, extValue));
                        } catch (Exception ex) {
                          // Do nothing
                        }
                      }
                    });
                  }
                  format.append("}]");
                  KeychainPolicy.LOGGER
                      .warn("[Keychain] default keychain context " + format.toString());
                  executionContext.setAttribute(KeychainPolicy.KEYCHAIN_KEY, format.toString());
                  policyChain.doNext(request, response);
                }
              }
            }
          });
        } else {
          policyChain.failWith(PolicyResult.failure(HttpStatusCode.INTERNAL_SERVER_ERROR_500,
              "Error on reading keychain data."));
        }

      }).exceptionHandler(e -> {
        KeychainPolicy.LOGGER.warn("[Keychain] *** ERROR ***: " + e.getLocalizedMessage());
        policyChain.failWith(PolicyResult.failure(HttpStatusCode.INTERNAL_SERVER_ERROR_500,
            "Error on reading keychain data."));
      }).end();
    } catch (Exception e) {
      KeychainPolicy.LOGGER.warn("[Keychain] *** ERROR ***: " + e.getLocalizedMessage());
      policyChain.failWith(PolicyResult.failure(HttpStatusCode.INTERNAL_SERVER_ERROR_500,
          "Error on reading keychain data."));
    }
  }
}
