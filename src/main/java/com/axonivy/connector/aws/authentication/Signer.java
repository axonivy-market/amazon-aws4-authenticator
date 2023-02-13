package com.axonivy.connector.aws.authentication;

import static com.axonivy.connector.aws.authentication.Constants.SIGNED_HEADERS;
import static com.axonivy.connector.aws.authentication.Constants.UTF8;
import static com.axonivy.connector.aws.authentication.Crypto.hash;
import static com.axonivy.connector.aws.authentication.Crypto.hmac;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.ext.Providers;

import org.apache.commons.codec.binary.Hex;

class Signer {

  private static final String HOST_SUFFIX = ".amazonaws.com";
  private static final String AWS4 = "AWS4";
  private static final String AWS4_REQUEST = "aws4_request";
  private static final String AWS_ALGORITHM = "AWS4-HMAC-SHA256";

  private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
          .withZone(ZoneId.of("UTC"));
  private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd")
          .withZone(ZoneId.of("UTC"));

  private final String regionName;
  private final String serviceName;
  private final String accessKey;
  private final String secretKey;
  private final Instant instant = Instant.now();
  private final String timeStamp;
  private final String dateStamp;
  private final ClientRequestContext request;
  private final String contentHash;

  Signer(ClientRequestContext request, Providers providers) throws NoSuchAlgorithmException, IOException {
    this.request = request;
    regionName = getRegionName(request);
    serviceName = getStringProperty(request, "serviceName");
    accessKey = getStringProperty(request, "accessKey");
    secretKey = getStringProperty(request, "secretKey");
    timeStamp = TIME_FORMATTER.format(instant);
    dateStamp = DATE_FORMATTER.format(instant);
    contentHash = new ContentHasher(request, providers).toHash();
  }

  public String contentHash() {
    return contentHash;
  }

  String getTimeStamp() {
    return timeStamp;
  }

  String sign() throws NoSuchAlgorithmException, InvalidKeyException {
    var credentialScope = getCredentialScope();
    var toSign = getStringToSign(credentialScope);
    var signatureKey = getSignatureKey();
    var signature = hmac(toSign, signatureKey);
    return authorization(credentialScope, signature);
  }

  private String getCredentialScope() {
    return new StringBuilder()
            .append(dateStamp)
            .append('/')
            .append(regionName)
            .append('/')
            .append(serviceName)
            .append('/')
            .append(AWS4_REQUEST)
            .toString();
  }

  private String getStringToSign(String credential) throws NoSuchAlgorithmException {
    return new StringBuilder()
            .append(AWS_ALGORITHM)
            .append('\n')
            .append(timeStamp)
            .append('\n')
            .append(credential)
            .append('\n')
            .append(getRequestHash())
            .toString();
  }

  private byte[] getSignatureKey() throws InvalidKeyException, NoSuchAlgorithmException {
    var sKey = AWS4 + secretKey;
    var kSecret = sKey.getBytes(UTF8);
    var kTimestamp = hmac(dateStamp, kSecret);
    var kRegion = hmac(regionName, kTimestamp);
    var kService = hmac(serviceName, kRegion);
    return hmac(AWS4_REQUEST, kService);
  }

  private String authorization(String credentialScope, byte[] signature) {
    return new StringBuilder()
            .append(AWS_ALGORITHM)
            .append(" ")
            .append("Credential=")
            .append(accessKey)
            .append('/')
            .append(credentialScope)
            .append(", ")
            .append("SignedHeaders=")
            .append(SIGNED_HEADERS)
            .append(", ")
            .append("Signature=")
            .append(Hex.encodeHexString(signature))
            .toString();
  }

  private String getRequestHash() throws NoSuchAlgorithmException {
    var canonicalRequest = new CanonicalRequest(request, timeStamp, contentHash);
    return hash(canonicalRequest.generate());
  }

  private static String getRegionName(ClientRequestContext request) {
    var configuration = request.getConfiguration();
    var value = configuration.getProperty("regionName");
    if (value instanceof String) {
      var str = value.toString();
      if (str != null && !str.isBlank()) {
        return str;
      }
    }
    var host = request.getUri().getHost();
    if (host == null || !host.endsWith(HOST_SUFFIX)) {
      throw new IllegalArgumentException("Cannot parse region name from url " + request.getUri() + ". Expect host to end with " + HOST_SUFFIX);
    }
    host = host.substring(0, host.length() - HOST_SUFFIX.length());
    var index = host.lastIndexOf('.');
    if (index < 0) {
      throw new IllegalArgumentException("Cannot parse region name from url " + request.getUri() + ". Expect to find . as delimiter before region");
    }
    var region = host.substring(index + 1, host.length());
    if (region.isBlank()) {
      throw new IllegalArgumentException("Cannot parse region name from url " + request.getUri() + ". Region part is blank");
    }
    return region;
  }

  private static String getStringProperty(ClientRequestContext request, String name) {
    var configuration = request.getConfiguration();
    var value = configuration.getProperty(name);
    if (!(value instanceof String)) {
      throw new IllegalArgumentException("No value configured for property " + name + ". Available properties are " + configuration.getPropertyNames());
    }
    var str = value.toString();
    if (str == null || str.isBlank()) {
      throw new IllegalArgumentException("Blank value configured for property " + name);
    }
    return str.trim();
  }
}
