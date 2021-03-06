/*
 *  X509Exception.java
 *
 *    Copyright 2018 Moriarty Software & Consulting Services
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 */

package com.morscs.web.authn.x509;

/**
 * When issues encountered while parsing X509 certificates.
 */
public class X509Exception extends Exception {

  public X509Exception(String message) {
    super(message);
  }

  public X509Exception(String message, Throwable cause) {
    super(message, cause);
  }
}
