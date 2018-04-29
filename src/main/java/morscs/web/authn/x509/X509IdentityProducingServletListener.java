/*
 *  X509IdentityProducingServletListener.java
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

package morscs.web.authn.x509;

import javax.enterprise.inject.Produces;
import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;

//@WebListener
public class X509IdentityProducingServletListener implements ServletRequestListener {

  private static final ThreadLocal<ServletRequest> SERVLET_REQUESTS = new ThreadLocal<>();

  @Override
  public void requestInitialized(ServletRequestEvent sre) {
    SERVLET_REQUESTS.set(sre.getServletRequest());
  }

  @Override
  public void requestDestroyed(ServletRequestEvent sre) {
    SERVLET_REQUESTS.remove();
  }

  private HttpServletRequest obtainHttp() {
    ServletRequest req = SERVLET_REQUESTS.get();
    return req instanceof HttpServletRequest ? (HttpServletRequest) req : null;
  }

  @Produces
  private X509Identity obtainX509Identity() throws X509Exception {
    return new X509Identity(X509Extraction.extractPrimarySubjectDnFromCert(X509Extraction
        .extractPrimaryCertFromChain(
            X509Extraction.extractCertChainFromRequestAttribute(obtainHttp()))));
  }
}


