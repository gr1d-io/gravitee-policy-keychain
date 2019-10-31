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

/**
 * @author Alexandre Santos (alexandre.santos at gr1d.io)
 * @author gr1d.io team
 */
public enum DefaultMethod {

  BASICAUTH("basicauth"), HEADER("header"), QUERY("query"), UNKOWN("unknown");

  private String name;

  DefaultMethod(String name) {
    this.name = name;
  }

  public String getName() {
    return name;
  }

  public static DefaultMethod get(String name) {
    for(DefaultMethod method : DefaultMethod.values()) {
      if (method.getName() == name) {
        return method;
      }
    }

    return DefaultMethod.UNKOWN;
  }
}

