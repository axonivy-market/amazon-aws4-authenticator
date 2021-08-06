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
  private final Providers providers;

  Signer(ClientRequestContext request, Providers providers) {
    this.providers = providers;
    this.request = request;
    regionName = getStringProperty(request, "regionName");
    serviceName = getStringProperty(request, "serviceName");
    accessKey = getStringProperty(request, "accessKey");
    secretKey = getStringProperty(request, "secretKey");
    timeStamp = TIME_FORMATTER.format(instant);
    dateStamp = DATE_FORMATTER.format(instant);
  }

  String getTimeStamp() {
    return timeStamp;
  }

  String sign() throws NoSuchAlgorithmException, InvalidKeyException, IOException {
    var credentialScope = getCredentialScope();
    var toSign = getStringToSign(credentialScope);
    var signatureKey = getSignatureKey();
    var signature = hmac(toSign, signatureKey);
    return authorization(credentialScope, signature);
  }

  private String getCredentialScope() {
    var builder = new StringBuilder();
    builder.append(dateStamp);
    builder.append('/');
    builder.append(regionName);
    builder.append('/');
    builder.append(serviceName);
    builder.append('/');
    builder.append(AWS4_REQUEST);
    return builder.toString();
  }

  private String getStringToSign(String credential) throws NoSuchAlgorithmException, IOException {
    var builder = new StringBuilder();
    builder.append(AWS_ALGORITHM);
    builder.append('\n');
    builder.append(timeStamp);
    builder.append('\n');
    builder.append(credential);
    builder.append('\n');
    var requestHash = getRequestHash();
    builder.append(requestHash);
    return builder.toString();
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
    var builder = new StringBuilder();
    builder.append(AWS_ALGORITHM);
    builder.append(" ");
    builder.append("Credential=");
    builder.append(accessKey);
    builder.append('/');
    builder.append(credentialScope);
    builder.append(", ");
    builder.append("SignedHeaders=");
    builder.append(SIGNED_HEADERS);
    builder.append(", ");
    builder.append("Signature=");
    builder.append(Hex.encodeHexString(signature));
    return builder.toString();
  }

  private String getRequestHash() throws NoSuchAlgorithmException, IOException {
    var canonicalRequest = new CanonicalRequest(request, timeStamp, providers);
    return hash(canonicalRequest.generate());
  }

  private static String getStringProperty(ClientRequestContext request, String name) {
    var configuration = request.getConfiguration();
    var value = configuration.getProperty(name);
    if (!(value instanceof String)) {
      throw new IllegalArgumentException("No value configured for property " + name
              + ". Available properties are " + configuration.getPropertyNames());
    }
    var str = value.toString();
    if (str == null || str.isBlank()) {
      throw new IllegalArgumentException("Blank value configured for property " + name);
    }
    return str.trim();
  }
}
