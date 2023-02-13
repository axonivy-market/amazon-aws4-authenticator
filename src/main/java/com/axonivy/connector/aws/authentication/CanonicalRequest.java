package com.axonivy.connector.aws.authentication;

import static com.axonivy.connector.aws.authentication.Constants.SIGNED_HEADERS;
import static com.axonivy.connector.aws.authentication.Constants.X_AMZ_DATE;
import static com.axonivy.connector.aws.authentication.Crypto.hash;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.security.NoSuchAlgorithmException;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Providers;

class CanonicalRequest {

  private static final byte[] EMPTY = new byte[0];
  private static final Annotation[] ANNOTATIONS = new Annotation[] {};

  private final ClientRequestContext request;
  private final String timeStamp;
  private final StringBuilder builder = new StringBuilder();
  private final Providers providers;

  CanonicalRequest(ClientRequestContext request, String timeStamp, Providers providers) {
    this.request = request;
    this.timeStamp = timeStamp;
    this.providers = providers;
  }

  String generate() throws NoSuchAlgorithmException, IOException {
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
    builder.append(request.getUri().getPath());
    builder.append('\n');
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

  private void appendEntityHash() throws NoSuchAlgorithmException, IOException {
    var entity = getEntity();
    var entityHash = hash(entity);
    builder.append(entityHash);
  }

  private byte[] getEntity() throws IOException {
    if (!request.hasEntity()) {
      return EMPTY;
    }
    var entity = request.getEntity();
    try (var baos = new ByteArrayOutputStream()) {
      var type = request.getEntityType();
      GenericType<?> genericType = new GenericType<>(type);
      @SuppressWarnings("unchecked")
      var messageBodyWriter = (MessageBodyWriter<Object>) providers.getMessageBodyWriter(
              genericType.getRawType(), genericType.getType(), ANNOTATIONS, MediaType.APPLICATION_JSON_TYPE);

      messageBodyWriter.writeTo(entity,
              genericType.getRawType(), genericType.getType(),
              ANNOTATIONS, MediaType.APPLICATION_JSON_TYPE,
              new MultivaluedHashMap<>(),
              baos);
      return baos.toByteArray();
    }
  }
}
