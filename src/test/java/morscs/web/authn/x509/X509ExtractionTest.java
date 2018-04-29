/*
 *  X509ExtractionTest.java
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import javax.mail.internet.InternetAddress;

public class X509ExtractionTest {
  private static final String EXPECTED_FULL_CN = "TARGARYEN.DAENERYS.MIDDLE.1234567890";
  private static final String EXPECTED_NO_MIDDLE_CN = "TARGARYEN.DAENERYS.1234567890";
  private static final String EXPECTED_FIRST_NAME = "DAENERYS";
  private static final String EXPECTED_LAST_NAME = "TARGARYEN";
  private static final String EXPECTED_MIDDLE_NAME = "MIDDLE";
  private static final long EXPECTED_EDIPI = 1234567890;
  private static final String EXPECTED_EMAIL = "daenerys.targeryen@dragonstone.got";

  private static final String[] SUPPORTED_FULL_SUBJECT_DN =
      {"CN=TARGARYEN.DAENERYS.MIDDLE.1234567890,OU=CONTRACTOR,OU=PKI,OU=DoD,O=U.S. Government,C=US",
          "CN=TARGARYEN.DAENERYS.MIDDLE.1234567890,OU=CONTRACTOR,OU=PKI,OU=DoD,O=U.S. Government,C=US",
          "CN=TARGARYEN.DAENERYS.MIDDLE.1234567890"};

  private static final String[] SUPPORTED_NO_MIDDLE_SUBJECT_DN =
      {"CN=TARGARYEN.DAENERYS.1234567890,OU=CONTRACTOR,OU=PKI,OU=DoD,O=U.S. Government,C=US",
          "CN=TARGARYEN.DAENERYS.1234567890,OU=CONTRACTOR,OU=PKI,OU=DoD,O=U.S. Government,C=US",
          "CN=TARGARYEN.DAENERYS.1234567890", "CN=TARGARYEN.DAENERYS.1234567890"};

  private static final String SUPPORTED_FULL_DN_CN = "TARGARYEN.DAENERYS.MIDDLE.1234567890";
  private static final String SUPPORTED_NO_MIDDLE_DN_CN = "TARGARYEN.DAENERYS.1234567890";

  private static final String[] INVALID_SUBJECT_DN =
      {"TARGARYEN", "TARGARYEN.DAENERYS.123", "", "CN="};

  // @formatter:off
  private static final String BASE64_CERT = "MIIGPjCCBCagAwIBAgICEA4wDQYJKoZIhvcNAQELBQAwYTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCVNhbiBEaWVnbzEQMA4GA1UECgwHc2FuZGJveDEXMBUGA1UEAwwOY2Euc2FuZGJveC5jb20wHhcNMTgwMzEwMjExMTQ2WhcNMTkwMzEwMjExMTQ2WjCBlDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoMB3NhbmRib3gxEzARBgNVBAsMCkNPTlRSQUNUT1IxDDAKBgNVBAsMA1BLSTEMMAoGA1UECwwDRG9EMS0wKwYDVQQDDCRUQVJHQVJZRU4uREFFTkVSWVMuTUlERExFLjEyMzQ1Njc4OTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDDOUQdWgWS9/IvBibXqlcu4aQqoS8LHZF6CrC6PKhSmEuJ0dChpceCiRSLJKQXBamv4A72IW5rnCtJU9jsIWcVRExTUMBsbHEspekRpmIBLKUIXSW7eLyX23A+oGuUnmuAnuNqu+SwWXf8li5mLb5LgBrKTzE5AMFBSRUcUVrNeAjEYy9BASZXxLVZL9QFvov+mD9UIGEwE1jNk6tRPh4zPmLdBBedWf1Wm+hIztL3eei3vxnb3As4O50XE2j0wrqXUfCvJyL9Toh8oIsZ1VjsWo2T42dM96fDUvH1jTorgbdj7QLh5p/cWAnAn1blCTUi82tPzG1JRh6XSIIjOg8Ibo6BKf1+ak9IGsOUYHKDU/5ZCJ6j7ZPASMdrOcBZRDWZJyjJqtINDvEjXYdHs6wLUsIfbv5nH+yb27wZSa1xsCqKR/Dz0n97MEHkmjv8az/G7u9aXUXop1CL1hO6ydKVJfDHcOnvVKLQFijx4x1JsqWL1arU1uTW5TWcolYsdMpejeaV2uR8yUaCDsf+GXUbIyMw1m0Ykh3laVyYriDWPQmtsMZjutcZX/YPRzGOSdyS6gsQvuMcyBExg5hRDS8rrC59aV1/6IGoSSH5sgKisQrWwIWjLUN0v5zBxWLFXCLlNRFAL6l2/bgXGVyJav1ztmkJ+lxaRBzDki3/oLcs1wIDAQABo4HLMIHIMAkGA1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgSwMAsGA1UdDwQEAwIF4DAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFEKnIkotDQ9h0ZVlGpHrxzWl6kvjMB8GA1UdIwQYMBaAFNM+DvafU4eCzHSZlQAK9PEuci1/MC0GA1UdEQQmMCSBImRhZW5lcnlzLnRhcmdlcnllbkBkcmFnb25zdG9uZS5nb3QwDQYJKoZIhvcNAQELBQADggIBAHtcTINWmww0ilWlVUhvXJVemXgXIcK8udC2D4HUm5tFpQDvZTZfl0ohVl5TTZ2+y6QO7Haksd0+Uw/7SEZvpqSXFPFO4ZNpq4SySueaUfst51k0z6kXSFyzcPJ1t0AKJVQAteoNqxJJ7R5ea5JvRe8fK4SGualkcqDvClwpV56AwGCpjKCRhfabL00hcsVm26yez9Zu8BHAOvx/sYxYjwsveoFpJQDLM/ENQ0O4D0IL2ietFfh+v4yjrZxuG8tdMlGB/TZfwtOLyGlXRoTn1izu5iahBK0K9C2ur42+3sukkKHuWx2+89qZOMwuisRlK6rZQH3DCXEQZ6jKL0lXOXiBt6vcA1iC+vV5tmjxd7V7HQORcVRXRyl+CGbLQv2TOfRfVhk3pM9JxVYijA6XP4YAE/PO1GPjl2e/QLYBd1o9a8SZkxGANe7VCOz50UfP8EVI7om+bUCI2k+VfdwVgfKJUeaU/4XU28Q/WrnHoflqyXnkrmli9R4U+Oqhn3OEUN0yASBbDpi/3T92+HP0BgOI4EnC1AGb9o+c2hzflu+aChMx840B0fdTp+Gk+r1/8P6tjQaJ+ljsJzrqCUHmaFd1sjUXDTGzUeo9Nm0Gz5Y0kTDvArNelnUicdQOpuhyaVFcKVr45++PX5CjZVAZqHD/Z2zofd+iL7i04q5EBpJd";

  private static final String BASE64_CERT_NOEMAIL = "MIIFvzCCA6egAwIBAgICEAcwDQYJKoZIhvcNAQELBQAwYTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCVNhbiBEaWVnbzEQMA4GA1UECgwHc2FuZGJveDEXMBUGA1UEAwwOY2Euc2FuZGJveC5jb20wHhcNMTgwMzEwMjAwMTE3WhcNMTkwMzEwMjAwMTE3WjCBxzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoMB3NhbmRib3gxEzARBgNVBAsMCkNPTlRSQUNUT1IxDDAKBgNVBAsMA1BLSTEMMAoGA1UECwwDRG9EMS0wKwYDVQQDDCRUQVJHQVJZRU4uREFFTkVSWVMuTUlERExFLjEyMzQ1Njc4OTAxMTAvBgkqhkiG9w0BCQEWImRhZW5lcnlzLnRhcmdlcnllbkBkcmFnb25zdG9uZS5nb3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCwjbT3jQeAkgDQNqm91C6+RgnCPEo0HyWt0nFYC5TBfnIkjtQbC383tJj1L36MrWqoUtjTBuS2KZqZN0XSasSz/WDUeHarBHBV0sjKbSc9IvZP/vCr+Ob4Jf4yn0sBoN0Xx3N0kuyrufcymSSM0ek73vRwecD9PIwJ/wtjev2l9mAKJRQb8Taui9uMLGI+oUViV7U40GwsdcN1hg1kZPqEgP86TUoCxZCpFeLfQ3yTW+4wTex+BtMQhUDgYhaltLMUBmpL37X3s62wbgaKmI1NLO6JKiygPDxyckLC4ux2H9wkKef3PRhGKSOTqXqxeW84DpXkAHFLAhYJLfQ9LkjIxfm75+PFTwU0iJCK4W8OkaYSGj8k1qjbGwkP5xzIuQz3bqDLlV8eI7i9dot4eioe6VBYbpTNfp/ucbCIDG4hBPisHETGnlqjJvkPiUJ3AKFCIG9QzLrREp7sZO2T9SnpivCIVijPjsLfYtbY0I8mealgSKuW4HcW0sjvbJJ80tqiU4SiUZlyhYb7NHqgd0UdG4W9MYnzhVcdhQYV5dT/Zvt3IgIeCejbcweSNFyGYPSv401OPTNoQs5yTqsBwOCGhbMXAUGNgJDrn3Y9Oed1qKyGsXO8Oo7U3/dbgbvxjTTBxDn4JQHc3kNs3mm5sVF9Hu8bYWkrweqac7whtK5m5QIDAQABoxowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DANBgkqhkiG9w0BAQsFAAOCAgEAY0TOZhandutUx/EKegC85u7fyYChjJCYBbfFBax37BuvrcGemOi0akIpNuVAtdlCyIOW1Qzg+k2BSU/UWEr5smfYyOlN0ZT/DkyYn4T/cnfRFKfzbO5gPr4mDJwcPKHmCIloigJbPOJAiAvKD0iAMyOUlNiFsXUdhYqFYPH0tQgCVZGdb8J5/tafkl8e4H1PW31j/ZeXrr9n9CQVTh2CaDSQUQY8jveD8O/1CpMiynr1hQuxYfSet77YEo9vF/+EpLbh7+7f8EHih9Gg5f6PQqlZ5eY97skkgowiFNc9oUkEzXIVnJSTGFRC6/DWoLAguVEZmB0FbAdlcLrDsMYrNVrlVRkqhM2j48fJElU0limWBCE0U8ljkFLwsQeUzbL/bcZXr1UpR2UWmAaVBpmmqXhGZ/DzzZMzDXupB9drl5T72nXl3PIZBUx7iCpa1+YbwzeLxbFxj2Khwootx2/Nx7Ej9Ufd1AeYWqKkSgZtkGUp/26386IVuYj8d/bLkYYJxwsnGE+v+/ZHzWK110pw6YZMP+RiVT3jvzMzdFp49BkHl/cjiOj2uSQAaXI7fJ3CDpecJfg96TxyWaBuStptvP6jf8+b349xXK6PRWYGmTNxKcg0AQzTsFte0hgYtGjIzfcAB9x89FY7j4IU0IaziqRAhQPguz/HC7T5UbwMUMM=";
  // @formatter:on

  @Test
  public void extractCnFromSubjectDn_validSubjectDn_shouldExtractCorrectCn() {
    for (String subject : SUPPORTED_FULL_SUBJECT_DN) {
      String cn = X509Extraction.extractCnFromSubjectDn(subject);
      assertEquals(EXPECTED_FULL_CN, cn, "incorrect cn extracted input(" + subject + ")");
    }
    for (String subject : SUPPORTED_NO_MIDDLE_SUBJECT_DN) {
      String cn = X509Extraction.extractCnFromSubjectDn(subject);
      assertEquals(EXPECTED_NO_MIDDLE_CN, cn, "incorrect cn extracted input(" + subject + ")");
    }
  }

  @Test
  public void extractCnFromSubjectDn_invalidSubjectDn_shouldReturnNull() {
    for (String subject : INVALID_SUBJECT_DN) {
      String cn = X509Extraction.extractCnFromSubjectDn(subject);
      assertNull(cn,
          "extracted identity from invalid subject input(" + subject + ") --> output(" + cn + ")");
    }
    assertThrows(NullPointerException.class, () -> X509Extraction.extractCnFromSubjectDn(null));
  }

  @Test
  public void extractCommonNameFromCn_validCn_shouldProduceCorrectCommonName()
      throws X509Exception {
    CommonName cnObj = X509Extraction.extractCommonNameFromCn(SUPPORTED_FULL_DN_CN);
    assertEquals(EXPECTED_FIRST_NAME, cnObj.getFirstName());
    assertEquals(EXPECTED_LAST_NAME, cnObj.getLastName());
    assertEquals(EXPECTED_MIDDLE_NAME, cnObj.getMiddleName());
    assertEquals(EXPECTED_EDIPI, cnObj.getEdipi());

    cnObj = X509Extraction.extractCommonNameFromCn(SUPPORTED_NO_MIDDLE_DN_CN);
    assertEquals(EXPECTED_FIRST_NAME, cnObj.getFirstName());
    assertEquals(EXPECTED_LAST_NAME, cnObj.getLastName());
    assertNull(cnObj.getMiddleName());
    assertEquals(EXPECTED_EDIPI, cnObj.getEdipi());
  }

  @Test
  public void extractCommonNameFromCn_invalidCn_shouldProduceException() {
    assertThrows(NullPointerException.class, ()
        -> X509Extraction.extractCommonNameFromCn(null));

    assertThrows(X509Exception.class, () ->
        X509Extraction.extractCommonNameFromCn("hello.world"));

    assertThrows(X509Exception.class, () ->
        X509Extraction.extractCommonNameFromCn("hello.world.middle.123xxx456"));

    assertThrows(X509Exception.class, () ->
        X509Extraction.extractCommonNameFromCn("hello.world.middle.unexpectedPart.11111"));
  }

  @Test
  public void buildCertChainFromBase64Encoding_validCert_shouldProduceCertObject() throws X509Exception {
    X509Certificate[] certChain = X509Extraction.buildCertChainFromBase64Encoding(BASE64_CERT);
    String cn = X509Extraction.extractCnFromSubjectDn(X509Extraction
        .extractPrimarySubjectDnFromCert(X509Extraction.extractPrimaryCertFromChain(certChain)));
    assertEquals(EXPECTED_FULL_CN, cn);

    certChain = X509Extraction.buildCertChainFromBase64Encoding(BASE64_CERT_NOEMAIL);
    cn = X509Extraction.extractCnFromSubjectDn(X509Extraction
        .extractPrimarySubjectDnFromCert(X509Extraction.extractPrimaryCertFromChain(certChain)));
    assertEquals(EXPECTED_FULL_CN, cn);
  }

  @Test
  public void extractPrimaryEmailFromCert_sanPresent_shouldIdentifyEmail() throws X509Exception {
    X509Certificate[] certChain = X509Extraction.buildCertChainFromBase64Encoding(BASE64_CERT);
    InternetAddress email = X509Extraction
        .extractPrimaryEmailFromCert(X509Extraction.extractPrimaryCertFromChain(certChain));
    assertEquals(EXPECTED_EMAIL, email.getAddress());
  }


  @Test
  public void extractPrimaryEmailFromCert_sanMissing_shouldThrowX509Exception() throws X509Exception {
    X509Certificate[] certChain = X509Extraction.buildCertChainFromBase64Encoding(BASE64_CERT_NOEMAIL);
    assertThrows(X509Exception.class, () ->
        X509Extraction.extractPrimaryEmailFromCert(X509Extraction.extractPrimaryCertFromChain(certChain)));
  }

}
