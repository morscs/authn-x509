/*
 *  X509Extraction.java
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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.servlet.http.HttpServletRequest;

/**
 * X509 Cert Utility Reader
 * <p>
 * Usage Tips:
 * <ol>
 * <li> 1. Start by getting the cert chain X509Certificate[]:
 *   <ul>
 *     <li>- extractCertChainFromRequestAttribute(HttpServletRequest request) </li>
 *     <li>- extractCertChainFromRequestHeader(HttpServletRequest request, String headerName)</li>
 *     <li>- buildCertChainFromBase64Encoding(String certEncoded)</li>
 *   </ul>
 * </li>
 * <li> 2. Identify the primary certificate  X509Certificate:
 *    <ul>
 *      <li>- extractPrimaryCertFromChain(X509Certificate[] certChain) </li>
 *    </ul>
 * </li>
 * <li> 3. Extract other stuff using the X509Certificate:
 *    <ul>
 *      <li>
 *        - extractPrimarySubjectDnFromCert <br>
 *        CN=TARGARYEN.DAENERYS.MIDDLE.1234567890,OU=CONTRACTOR,OU=PKI,OU=DoD,O=U.S. Government,C=US
 *      </li>
 *      <li>
 *        -  extractCnFromSubjectDn(String subjectDn) <br>
 *        TARGARYEN.DAENERYS.MIDDLE.1234567890
 *      </li>
 *      <li>
 *        extractCommonNameFromCn(String cn) <br>
 *        CommonName object (data structure to hold parsed cn data: lastName, firstName, edipi)
 *      </li>
 *      <li>
 *        - extractPrimaryEmailFromCert(X509Cert cert) <br>
 *        InternetAddress (object wrapper for email)
 *      </li>
 *   </ul>
 * </li>
 * </ol>
 */
public class X509Extraction {
  private static final int IDX_LAST_NAME = 0;
  private static final int IDX_FIRST_NAME = 1;
  private static final int IDX_MIDDLE_NAME = 2; // if present
  private static final int MAX_CN_PARTS = 4;

  /**
   * Extract X509 certificate chain from request.
   *
   * @param request servlet request
   * @return cert chain
   */
  public static X509Certificate[] extractCertChainFromRequestAttribute(HttpServletRequest request) {
    return (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
  }

  /**
   * Extract certificate data from named request header.
   *
   * @param request servlet request
   * @param headerName http header name
   * @return cert chain
   * @throws X509Exception when error converting header value to certificate object
   */
  public static X509Certificate[] extractCertChainFromRequestHeader(HttpServletRequest request,
      String headerName) throws X509Exception {
    return buildCertChainFromBase64Encoding(request.getHeader(headerName));
  }

  /**
   * Decode certificate chain from base 64 encoded certificate data.
   *
   * @param certEncoded base64 encoded cert chain
   * @return cert chain
   * @throws X509Exception when any error building from encoded data
   * @throws IllegalArgumentException when given invalid encoding data
   */
  public static X509Certificate[] buildCertChainFromBase64Encoding(String certEncoded)
      throws X509Exception {
    byte[] bytes = Base64.getDecoder().decode(certEncoded);
    BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(bytes));

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      List<X509Certificate> certChain = new ArrayList<>();
      while (bis.available() > 0) {
        certChain.add((X509Certificate) cf.generateCertificate(bis));
      }
      return certChain.toArray(new X509Certificate[0]);
    } catch (IOException | CertificateException exc) {
      throw new X509Exception("failed to read certificate from base64 data", exc);
    }
  }

  /**
   * Extract the first certificate in the chain as the primary client identity.
   *
   * @param certChain certificate chain
   * @return primary certificate
   * @throws X509Exception when certChain is null or empty
   */
  public static X509Certificate extractPrimaryCertFromChain(X509Certificate[] certChain)
      throws X509Exception {
    if (certChain == null) {
      throw new X509Exception("cert chain not available");
    }
    if (certChain.length == 0) {
      throw new X509Exception("cert chain empty");
    }
    return certChain[0];
  }

  /**
   * Extract subject DN from first certificate in chain.
   *
   * @param certObj certificate object
   * @return subject DN formatted string, null if extraction failed.
   */
  public static String extractPrimarySubjectDnFromCert(X509Certificate certObj)
      throws X509Exception {
    Principal subject = certObj.getSubjectDN();
    if (subject == null) {
      throw new X509Exception("null subject in X509Certificate object");
    }
    return subject.getName();
  }

  /**
   * Extract email address from certificate.
   *
   * @param cert primary client certificate
   * @return email object
   * @throws X509Exception if unable to identify email
   */
  public static InternetAddress extractPrimaryEmailFromCert(X509Certificate cert)
      throws X509Exception {
    String emailString = null;
    try {
      Collection<List<?>> sans = cert.getSubjectAlternativeNames();
      if (sans != null && sans.size() > 0) {
        for (List<?> item : sans) {
          Integer type = (Integer) item.get(0);
          if (type == 1) {
            emailString = (String) item.get(1);
            break;
          }
        }
        if (emailString == null || emailString.isEmpty()) {
          throw new X509Exception("email type found in SAN, but value was null or empty");
        }
        return new InternetAddress(emailString);
      }
      throw new X509Exception("Subject Alternative List is empty");
    } catch (CertificateParsingException exc) {
      throw new X509Exception("failed to parse Subject Alternative Names from cert", exc);
    } catch (AddressException exc) {
      throw new X509Exception("failed to parse email address string: " + emailString, exc);
    }
  }

  /**
   * Parse the CN string from a DN as formatted in a typical TLS certificate.
   *
   * @param subjectDn formatted DN expected to include CN stanza
   * @return common name or null if not found
   * @throws NullPointerException when subjectDn parameter is null
   */
  public static String extractCnFromSubjectDn(String subjectDn) {
    String[] parts = subjectDn.split(",");
    for (String nvp : parts) {
      String[] pair = nvp.split("=");
      if (pair.length == 2 && "CN".equalsIgnoreCase(pair[0].trim())) {
        return pair[1].trim();
      }
    }
    return null;
  }

  /**
   * Extract commmon name object with last name / first name and edipi from cn string.
   *
   * @param cn common name string from certificate
   * @return cn information in parsed object form
   * @throws X509Exception if cn format is unparseable
   */
  public static CommonName extractCommonNameFromCn(String cn) throws X509Exception {
    String[] parts = cn.split("\\.");
    if (parts.length == MAX_CN_PARTS || parts.length == MAX_CN_PARTS - 1) {
      String lastName = parts[IDX_LAST_NAME];
      String firstName = parts[IDX_FIRST_NAME];
      String middleName = parts.length < MAX_CN_PARTS ? null : parts[IDX_MIDDLE_NAME];
      String edipiString = parts[parts.length - 1];
      long edipi;
      try {
        edipi = Long.parseLong(edipiString);
      } catch (NumberFormatException exc) {
        throw new X509Exception(
            "failed to parse edipi from string " + edipiString + " in CN " + cn);
      }
      return new CommonName(edipi, lastName, firstName, middleName);
    }
    throw new X509Exception(
        "unexpected parts in cn " + cn + ", expected 3-4, but parsed " + parts.length);
  }
}
