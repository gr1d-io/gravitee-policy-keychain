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
package io.gravitee.policy.keychain.configuration;

import java.util.ArrayList;
import java.util.List;
import io.gravitee.policy.api.PolicyConfiguration;

/**
 * @author Diogo Aihara (diogo at gr1d.io)
 * @author Alexandre Tolstenko (tolstenko at gr1d.io)
 * @author gr1d.io team
 */
public class KeychainPolicyConfiguration implements PolicyConfiguration {
    private String keychainUrl;
    private boolean mandatory;
    private DefaultMethod method;
    private List<DefaultParameter> addParameters = new ArrayList<>();

    public List<DefaultParameter> getAddParameters() {
      return addParameters;
    }

    public void setAddParameters(List<DefaultParameter> addParameters) {
      this.addParameters = addParameters;
    }

    public DefaultMethod getMethod() {
        return method;
    }

    public void setMethod(DefaultMethod method) {
        this.method = method;
    }

    public boolean getMandatory() {
      return mandatory;
    }

    public void setMandatory(boolean mandatory) {
      this.mandatory = mandatory;
    }

    public String getKeychainUrl(){
        return this.keychainUrl;
    }

    public void setKeychainUrl(String keychainUrl) {
        this.keychainUrl = keychainUrl;
    }
}
