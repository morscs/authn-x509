# authn-x509

Authentication helper for extracting X509 certificate information from an http/s request.

## Configuration 

Include the library in your deployment.

        <dependency>
          <groupId>com.morscs</groupId>
          <artifactId>authn-x509</artifactId>
          <version>0.0.1</version>
          <packaging>jar</packaging>
        </dependency>        

## Usage

1. Start by getting the cert chain X509Certificate[]:

    * extractCertChainFromRequestAttribute(HttpServletRequest request) </li>
    * extractCertChainFromRequestHeader(HttpServletRequest request, String headerName)</li>
    * buildCertChainFromBase64Encoding(String certEncoded)</li>
    
2. Identify the primary certificate  X509Certificate:

    * extractPrimaryCertFromChain(X509Certificate[] certChain) </li>
    
3. Extract other stuff using the X509Certificate:

    * extractPrimarySubjectDnFromCert <br/>
    
            CN=TARGARYEN.DAENERYS.MIDDLE.1234567890,OU=CONTRACTOR,OU=PKI,OU=DoD,O=U.S. Government,C=US
            
    * extractCnFromSubjectDn(String subjectDn) <br/>
    
            TARGARYEN.DAENERYS.MIDDLE.1234567890
            
    * extractCommonNameFromCn(String cn) <br/>
    
            CommonName object (data structure to hold parsed cn data: lastName, firstName, edipi)
            
    * extractPrimaryEmailFromCert(X509Cert cert) <br/>
    
            InternetAddress (object wrapper for email)
            
