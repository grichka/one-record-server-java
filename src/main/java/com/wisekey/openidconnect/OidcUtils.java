package com.wisekey.openidconnect;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.StringTokenizer;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

public class OidcUtils {
    /** The algorithm used to sign the JWT. */
    private static final String JWT_ALGORITHM = "SHA256withRSA";	  
    private String oidcRelativePath = "/.well-known/openid-configuration";
    private final RestWrapper callApi;
    
    public OidcUtils() {
        callApi = new RestWrapper();
    }
    
    public OidcUtils(final String path) {
        this.oidcRelativePath = path;
        callApi = new RestWrapper();
    }

    public ResponseTokenInfo getIDToken(final String authorizationCode, final String serverUri, 
            final String clientId, final String clientSecret, final String callbackUri) throws OidcException {
        
        String body = "";
        try {
            final RestTemplate restTemplate = callApi.createTemplate(null, null);
            // Create headers
            final HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
            final String credentials = clientId + ":" + clientSecret;
            headers.add("Authorization", "Basic " + base64Encode(credentials));
            // Create body
            final MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("client_id", clientId);
            map.add("code", authorizationCode);
            map.add("grant_type", "authorization_code");
            map.add("redirect_uri", callbackUri);
            final HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
            body = callApi.request(restTemplate, serverUri, HttpMethod.POST, request);
            final ResponseTokenInfo data = ResponseTokenInfo.FromJson(body);
            if (data != null) {
                data.setRaw(body);
            }
            return data;
        } catch (final Exception e) {
            throw new OidcException("Can not get the discovery document", e);
        }
    }

    public JwtTokenInfo getJwtTokenInfo(final String token) throws OidcException, TokenException {
        if (isStringEmpty(token)) {
            throw new TokenException("Token must be not empty.");
        }
        // Get parts of token
        final StringTokenizer st = new StringTokenizer(token, ".");
        final String jwtHeader = st.nextToken();
        final String jwtClaims = st.nextToken();
        final String jwtSignature = st.nextToken();
        // Get details token
        final String decodedString;
        final JwtTokenInfo tempClaim;
        try {
            decodedString = base64Decode(jwtClaims);
            tempClaim = loadJson(decodedString, JwtTokenInfo.class);
        }catch(Exception e) {
            throw new TokenException("Can not parse claim.", e);
        }
        // Set data
        final JwtTokenInfo result = new JwtTokenInfo();
        result.setRaw(token);
        result.setHeadersRaw(jwtHeader);
        result.setClaimsRaw(jwtClaims);
        result.setSignatureRaw(jwtSignature);
        if (tempClaim != null) {
            result.setClaimISS(tempClaim.getClaimISS());
            result.setExpired(tempClaim.getExpired());
            result.setAuthenTime(tempClaim.getAuthenTime());
        }
        return result;
    }
    
    public DiscoveryDocument getDiscoveryDocument(String url) throws OidcException {        
        url = url + oidcRelativePath;
        String body = "";
        try {
            final RestTemplate restTemplate = callApi.createTemplate(null, null);
            body = callApi.request(restTemplate, url, HttpMethod.GET, null);
            final DiscoveryDocument data = loadJson(body, DiscoveryDocument.class);
            if (data != null) {
                data.setRaw(body);
            }
            return data;
        } catch (final Exception e) {
            throw new OidcException("Can not get the discovery document", e);
        }
    }

    public ResponseJwks getJwksInfo(final String url) throws OidcException {
        try {
            final RestTemplate restTemplate = callApi.createTemplate(null, null);
            final String body = callApi.request(restTemplate, url, HttpMethod.GET, null);
            final ResponseJwks data = loadJson(body, ResponseJwks.class);
            if (data != null) {
                data.setRaw(body);
            }
            return data;
        } catch (final Exception e) {
            throw new OidcException("Can not get the Jwks information", e);
        }
    }
    
    public String getSKI(final String token)
            throws InvalidKeySpecException, NoSuchAlgorithmException, OidcException, TokenException {
        // Get token info
        final JwtTokenInfo jwtInfo = getJwtTokenInfo(token);
        if (jwtInfo == null || validateToken(jwtInfo)) {
            throw new TokenException("Token is invalid format.");
        }
        return getSKI(jwtInfo);
    }
    
    public String getSKI(final JwtTokenInfo jwtInfo) 
            throws InvalidKeySpecException, NoSuchAlgorithmException, OidcException, TokenException {
        if (isStringEmpty(jwtInfo.getClaimISS())){
            throw new TokenException("Claim is invalid format.");
        }
        final DiscoveryDocument disDoc = getDiscoveryDocument(jwtInfo.getClaimISS());
        if (disDoc == null) {
            throw new TokenException("Token is invalid format.");
        }
        if (isStringEmpty(disDoc.getJwksUri())){
            throw new TokenException("Token is invalid format.");
        }
        final ResponseJwks response = getJwksInfo(disDoc.getJwksUri());
        if (response == null) {
            throw new OidcException("Could not request to odic server.");
        }
        final ResponseJwksItem last = response.getLastSignKey();
        if (last == null) {
            throw new OidcException("Not found signing public key.");
        }
        final String n = last.getN();
        if (isStringEmpty(n)) {
            throw new OidcException("Signing public key is invalid format.");
        }
        final String e = last.getE();
        if (isStringEmpty(e)) {
            throw new OidcException("Signing public key is invalid format.");
        }
        // Get public key
        final BigInteger modulus = new BigInteger(1, base64UrlDecode(n));
        final BigInteger publicExponent = new BigInteger(1, base64UrlDecode(e));
        final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        final PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
        verifySignature(jwtInfo, publicKey);
        // Return Subject Key Identifier with hex format
        return getSKI(publicKey);
    }
    
    public String getSKI(final PublicKey publicKey) throws NoSuchAlgorithmException {
        // Get Subject Key Identifier
        final SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
        final byte[] arrResult = ski.getKeyIdentifier();
        // Return Subject Key Identifier with hex format
        return encodeHexString(arrResult);   
    }
    
    public PublicKey getOidcPublicKey(final String token) throws OidcException {
        try {
            // Get token info
            final JwtTokenInfo jwtInfo = getJwtTokenInfo(token);
            if (jwtInfo == null) {
                throw new OidcException("Token is invalid format");
            }
            if (isStringEmpty(jwtInfo.getClaimISS())){
                throw new OidcException("Token is invalid format");
            }
            final DiscoveryDocument disDoc = getDiscoveryDocument(jwtInfo.getClaimISS());
            if (disDoc == null) {
                throw new OidcException("Token is invalid format");
            }
            if (isStringEmpty(disDoc.getJwksUri())){
                throw new OidcException("Token is invalid format");
            }
            final ResponseJwks response = getJwksInfo(disDoc.getJwksUri());
            if (response == null) {
                throw new OidcException("Token is invalid format");
            }
            final ResponseJwksItem last = response.getLastKey();
            if (last == null) {
                throw new OidcException("Token is invalid format");
            }
            final String n = last.getN();
            if (isStringEmpty(n)) {
                throw new OidcException("Token is invalid format");
            }
            final String e = last.getE();
            if (isStringEmpty(e)) {
                throw new OidcException("Token is invalid format");
            }
            // Get public key
            final BigInteger modulus = new BigInteger(1, base64UrlDecode(n));
            final BigInteger publicExponent = new BigInteger(1, base64UrlDecode(e));
            final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
            return KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
        } catch (final Exception e) {
            throw new OidcException("Can not get public key", e);
        }
    }
    
    public PublicKey getOidcPublicKey(final JwtTokenInfo jwtInfo) throws OidcException {
        try {
            // Get token info
            if (isStringEmpty(jwtInfo.getClaimISS())){
                throw new OidcException("Token is invalid format");
            }
            final DiscoveryDocument disDoc = getDiscoveryDocument(jwtInfo.getClaimISS());
            if (disDoc == null) {
                throw new OidcException("Token is invalid format");
            }
            if (isStringEmpty(disDoc.getJwksUri())){
                throw new OidcException("Token is invalid format");
            }
            final ResponseJwks response = getJwksInfo(disDoc.getJwksUri());
            if (response == null) {
                throw new OidcException("Token is invalid format");
            }
            final ResponseJwksItem last = response.getLastKey();
            if (last == null) {
                throw new OidcException("Token is invalid format");
            }
            final String n = last.getN();
            if (isStringEmpty(n)) {
                throw new OidcException("Token is invalid format");
            }
            final String e = last.getE();
            if (isStringEmpty(e)) {
                throw new OidcException("Token is invalid format");
            }
            // Get public key
            final BigInteger modulus = new BigInteger(1, base64UrlDecode(n));
            final BigInteger publicExponent = new BigInteger(1, base64UrlDecode(e));
            final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
            return KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
        } catch (final Exception e) {
            throw new OidcException("Can not get public key", e);
        }
    }
    
    public PublicKey getOidcPublicKeyWithJwksUri(final String jwksUri) throws OidcException {
        try {
            if (isStringEmpty(jwksUri)) {
                throw new OidcException("JwksUri is empty");
            }
            final ResponseJwks response = getJwksInfo(jwksUri);
            if (response == null) {
                throw new OidcException("Token is invalid format");
            }
            final ResponseJwksItem last = response.getLastKey();
            if (last == null) {
                throw new OidcException("Token is invalid format");
            }
            final String n = last.getN();
            if (isStringEmpty(n)) {
                throw new OidcException("Token is invalid format");
            }
            final String e = last.getE();
            if (isStringEmpty(e)) {
                throw new OidcException("Token is invalid format");
            }
            // Get public key
            final BigInteger modulus = new BigInteger(1, base64UrlDecode(n));
            final BigInteger publicExponent = new BigInteger(1, base64UrlDecode(e));
            final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
            return KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
        } catch (final Exception e) {
            throw new OidcException("Can not get public key", e);
        }
    }
    
    public static boolean isStringEmpty(String str) {
        if (str == null) return true;
        if ("".equals(str)) return true;
        final String temp = str + "";
        str = temp.trim();
        if ("".equals(str)) return true;
        return false;
    }
    
    public static <T> T loadJson(final String jsonString, final Class<T> targetType) throws JsonSyntaxException {
        if (isStringEmpty(jsonString)) {
            return null;
        }        
        final Gson converter = new Gson();
        final T data = converter.fromJson(jsonString, targetType);
        return data;
    }

    private boolean validateToken(JwtTokenInfo token) {
        if (isStringEmpty(token.getSignatureRaw())){
            return false;
        }
        final long currentTS = getCurrentTimeStamp();
        if (currentTS < token.getAuthenTime() || currentTS > token.getExpired() ) {
            return false;
        }
        return true;
    }
    
    private boolean verifySignature(final JwtTokenInfo token, final PublicKey publicKey) throws TokenException {
        try {
            // Decode the signature we got from the server
            final byte[] jwtExpectedSig = base64UrlDecode(token.getSignatureRaw());
            // Validate the signature.
            final Signature sig = Signature.getInstance(JWT_ALGORITHM);
            sig.initVerify(publicKey);
            sig.update(new String(token.getHeadersRaw() + "." + token.getClaimsRaw()).getBytes());
            return sig.verify(jwtExpectedSig);
        } catch (final Exception ex) {
            throw new TokenException("Signature is mismatch.", ex);
        }
    }

    private long getCurrentTimeStamp() {
        //TimeZone.setDefault(TimeZone.getTimeZone("Etc/UTC"));
        final Instant instant = Instant.now();
        final long timeStampMillis = instant.toEpochMilli();
        return timeStampMillis / 1000;
    }
    
    private byte[] base64UrlDecode(final String strBase64) {
        return org.springframework.util.Base64Utils.decodeFromUrlSafeString(strBase64);
    }
    
    private String base64Decode(final String strEncodedBase64) throws IllegalArgumentException {
        final byte[] resultArr = Base64.getDecoder().decode(strEncodedBase64);
        return new String(resultArr);
    }
    
    private String base64Encode(final String str) {
        return Base64.getEncoder().encodeToString(str.getBytes());
    }
    
    private String byteToHex(final byte num) {
        final char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }
    
    private String encodeHexString(final byte[] byteArray) {
        final StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }
}