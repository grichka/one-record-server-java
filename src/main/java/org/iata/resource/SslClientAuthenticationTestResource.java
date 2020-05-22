package org.iata.resource;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import org.bouncycastle.asn1.x509.GeneralName;

import com.google.gson.Gson;
import com.wisekey.ocsp.OcspUtils;
import com.wisekey.openidconnect.OidcUtils;
import com.wisekey.openidconnect.OidcException;
import com.wisekey.openidconnect.TokenException;
import io.swagger.annotations.ApiOperation;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

@RestController
@RequestMapping(value = "/")
public class SslClientAuthenticationTestResource {

  private final HttpServletRequest request;
  private final Environment env;
  private static final String BEARER = "Bearer ";

  @Inject
  public SslClientAuthenticationTestResource(HttpServletRequest request, Environment env) {
    this.request = request;
    this.env = env;
  }

  @RequestMapping(method = GET, value = "/sslclientauthenticationtest", produces = { MediaType.TEXT_PLAIN_VALUE })
  @ApiOperation(value = "Returns the distinguished name for the received SSL client certificate")
  public ResponseEntity<String> doIt() {
    X509Certificate[] clientCertificateChain = (X509Certificate[]) request
        .getAttribute("javax.servlet.request.X509Certificate");
    X509Certificate clientCertificate = clientCertificateChain[0];    
    String token = request.getHeader("Authorization");
    String tmpTk = token.toLowerCase();
    if (tmpTk == null || tmpTk.length() <= BEARER.length()) {
      return new ResponseEntity<>(String.format("Client Error: Token is invalid."),
          HttpStatus.NON_AUTHORITATIVE_INFORMATION);
    }
    if (tmpTk.startsWith(BEARER)) {
      token = token.substring(BEARER.length());
    }
    OidcUtils oidcUtils = new OidcUtils();
    final String ski;
    try{
      ski = oidcUtils.getSKI(token);
    }catch(TokenException te){
      return new ResponseEntity<>(String.format("Client Error: %s", te.getMessage()),
          HttpStatus.BAD_REQUEST);
    }catch(OidcException oe) {
      return new ResponseEntity<>(String.format("Odic Server Error: %s", oe.getMessage()),
          HttpStatus.INTERNAL_SERVER_ERROR);
    }catch(Exception e) {
      return new ResponseEntity<>(String.format("Internal Server Error: %s", e.getMessage()),
          HttpStatus.INTERNAL_SERVER_ERROR);
    }

    HashMap<String, Object> retObj = new HashMap<>();
    retObj.put("odic.ski", ski);
    OcspUtils ocspUtils = new OcspUtils(env.getProperty("ocsp.cachedDir"));
    try {
      X500Principal subjectDN = clientCertificate.getSubjectX500Principal();
      retObj.put("client.cert.subjectDN", subjectDN.getName(X500Principal.CANONICAL));
      Collection<List<?>> sans = clientCertificate.getSubjectAlternativeNames();
      String sanString = "";
      if (sans == null) {
        sanString = "SANs are null.";
      } else {
        for (final List<?> item : sans) {
          if (item.size() < 2) {
            System.out.println("item.size < 2");
            continue;
          }
          Object data = null;
          switch ((Integer) item.get(0)) {
          case GeneralName.uniformResourceIdentifier:
          case GeneralName.dNSName:
          case GeneralName.iPAddress:
            data = item.get(1);
            if (data instanceof String) {
              sanString += ((String) data) + ", ";
            } else {
              System.out.println("data is not String");
            }
            break;
          default:
            System.out.println("we don't care other cases");
          }
        }
      }
      retObj.put("client.cert.SAN", sanString);
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
      retObj.put("client.cert.stats", certStatus);
      retObj.put("client.cert.statsdesc", statsDesc);
      X500Principal issuer = clientCertificate.getIssuerX500Principal();
      retObj.put("client.cert.issuer", issuer.getName(X500Principal.CANONICAL));
      retObj.put("client.cert.notafter", clientCertificate.getNotAfter().toString());
      retObj.put("client.cert.notbefore", clientCertificate.getNotBefore().toString());
      Gson gson = new Gson();
      String jsonString = gson.toJson(retObj);
      return new ResponseEntity<>(jsonString, httpStats);
    } catch (Exception e) {
      return new ResponseEntity<>(String.format("Internal Server Error: %s", e.getMessage()),
          HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

}
