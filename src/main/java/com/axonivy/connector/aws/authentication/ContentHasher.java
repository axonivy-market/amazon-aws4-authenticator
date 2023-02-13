package com.axonivy.connector.aws.authentication;

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

class ContentHasher {

  private static final byte[] EMPTY = new byte[0];
  private static final Annotation[] ANNOTATIONS = new Annotation[] {};

  private final ClientRequestContext request;
  private final Providers providers;

  ContentHasher(ClientRequestContext request, Providers providers) {
    this.request = request;
    this.providers = providers;
  }

  String toHash() throws NoSuchAlgorithmException, IOException {
    var entity = getEntity();
    var entityHash = Crypto.hash(entity);
    return entityHash;
  }

  private byte[] getEntity() throws IOException {
    if (!request.hasEntity()) {
      return EMPTY;
    }

    var entity = request.getEntity();

    // works at least for all byte payloads
    if (entity instanceof byte[]) {
      return (byte[]) entity;
    }

    // TODO only works with json payloads properly
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
