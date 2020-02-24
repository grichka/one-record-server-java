package org.iata.resource;

import com.wisekey.ocsp.OcspUtils;
import io.swagger.annotations.ApiOperation;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.security.cert.X509Certificate;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

@RestController
@RequestMapping(value = "/sslclientauthenticationtest")
public class SslClientAuthenticationTestResource {

  private final HttpServletRequest request;
  private final Environment env;

  @Inject
  public SslClientAuthenticationTestResource(HttpServletRequest request, Environment env) {
    this.request = request;
    this.env = env;
  }

  @RequestMapping(method = GET, value = "/", produces = {MediaType.TEXT_PLAIN_VALUE})
  @ApiOperation(value = "Returns the distinguished name for the received SSL client certificate")
  public ResponseEntity<String> doIt() {
    X509Certificate[] clientCertificateChain = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
    X509Certificate clientCertificate = clientCertificateChain[0];
    OcspUtils ocspUtils = new OcspUtils(env.getProperty("ocsp.cachedDir"));

    try {
      Principal subjectDN = clientCertificate.getSubjectDN();
      String certStatus = ocspUtils.validate(clientCertificate);
      String statsDesc = ocspUtils.getDescStatus(certStatus);
      HttpStatus httpStats;
      if (!certStatus.equals(OcspUtils.CERT_STATUS_GOOD) && !certStatus.equals(OcspUtils.CERT_STATUS_EXPIRED)
          && !certStatus.equals(OcspUtils.CERT_STATUS_REVOKED)) {
        if (certStatus.equals(OcspUtils.CERT_STATUS_BAD_CRL) || certStatus.equals(OcspUtils.CERT_STATUS_NO_CRL)) {
          certStatus = OcspUtils.CERT_STATUS_GOOD;
          httpStats = HttpStatus.OK;
        } else {
          certStatus = OcspUtils.CERT_STATUS_UNKNOWN;
          httpStats = HttpStatus.BAD_REQUEST;
        }
      } else {
        httpStats = HttpStatus.OK;
      }
      return new ResponseEntity<>(String.format(
          "Server side received (and validated) the following client certificate:\n\r\t{ Certificate-Info: %s; Certificate-Status: %s; Status-Description: %s}",
          subjectDN, certStatus, statsDesc), httpStats);
    } catch (Exception e) {
      return new ResponseEntity<>(String.format("Internal Server Error: %s", e.getMessage()),
          HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

}
