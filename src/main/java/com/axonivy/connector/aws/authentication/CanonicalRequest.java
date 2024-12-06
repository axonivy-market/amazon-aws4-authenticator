package com.axonivy.connector.aws.authentication;

import static com.axonivy.connector.aws.authentication.Constants.SIGNED_HEADERS;
import static com.axonivy.connector.aws.authentication.Constants.X_AMZ_DATE;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import javax.ws.rs.client.ClientRequestContext;

class CanonicalRequest {

  private final ClientRequestContext request;
  private final String timeStamp;
  private final StringBuilder builder = new StringBuilder();
  private final String contentHash;

  CanonicalRequest(ClientRequestContext request, String timeStamp, String contentHash) {
    this.request = request;
    this.timeStamp = timeStamp;
    this.contentHash = contentHash;
  }

  String generate() {
    appendMethod();
    appendPath();
    appendQuery();
    appendCanonicalHeaders();
    appendSignedHeaders();
    appendEntityHash();
    return builder.toString();
  }

  private void appendMethod() {
    builder.append(request.getMethod());
    builder.append('\n');
  }

  private void appendPath() {
    var path = request.getUri().getPath();
    if (path == null || path.isEmpty()) {
      path = "/";
    }
    try {
      var encodedPath = URLEncoder.encode(path, StandardCharsets.UTF_8.toString())
              .replace("%2F", "/")
              .replace("%7E", "~")
              .replace("*", "%2A")
              .replace("+", "%20");
      builder.append(encodedPath);
      builder.append('\n');
    } catch (UnsupportedEncodingException ex) {
      throw new RuntimeException("Unable to encode path " + path, ex);
    }
  }

  private void appendQuery() {
    var query = request.getUri().getQuery();
    if (query != null && !query.isBlank()) {
      builder.append(query);
    }
    builder.append('\n');
  }

  private void appendCanonicalHeaders() {
    builder.append("host:");
    builder.append(request.getUri().getHost());
    var port = request.getUri().getPort();
    if (port != -1) {
      builder.append(":");
      builder.append(port);
    }
    builder.append('\n');
    builder.append(X_AMZ_DATE);
    builder.append(':');
    builder.append(timeStamp);
    builder.append('\n');
    builder.append('\n');
  }

  private void appendSignedHeaders() {
    builder.append(SIGNED_HEADERS);
    builder.append('\n');
  }

  private void appendEntityHash() {
    builder.append(contentHash);
  }
}
