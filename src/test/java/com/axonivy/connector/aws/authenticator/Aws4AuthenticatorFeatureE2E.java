package com.axonivy.connector.aws.authenticator;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.glassfish.jersey.logging.LoggingFeature;
import org.junit.jupiter.api.Test;

import com.axonivy.connector.aws.authentication.Aws4AuthenticationFeature;

import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response.Status;

class Aws4AuthenticatorFeatureE2E {

  private static final Logger LOGGER = Logger.getLogger(Aws4AuthenticatorFeatureE2E.class.getName());
  private static final LoggingFeature LOGGING = new LoggingFeature(
      LOGGER,
      Level.INFO,
      LoggingFeature.Verbosity.PAYLOAD_ANY,
      8192);

  @Test
  void authenticator_with_regionName() {

    var client = ClientBuilder.newBuilder()
        .register(LOGGING)
        .register(Aws4AuthenticationFeature.class)
        .property("accessKey", getAccessKey())
        .property("secretKey", getSecretKey())
        .property("regionName", "eu-central-1")
        .property("serviceName", "lex")
        .build();

    var response = client
        .target("https://runtime-v2-lex.eu-central-1.amazonaws.com")
        .path("/bots/{botId}/botAliases/{botAliasId}/botLocales/{localeId}/sessions/{sessionId}/text")
        .resolveTemplate("botId", "IMRTYQC6BN")
        .resolveTemplate("botAliasId", "GXHT5U6V6K")
        .resolveTemplate("sessionId", "10")
        .resolveTemplate("localeId", "en_US")
        .request()
        .post(Entity.entity("{\"text\":\"Book Hotel\"}", MediaType.APPLICATION_JSON));

    assertThat(response.getStatusInfo()).isEqualTo(Status.OK);
  }

  @Test
  void authenticator_without_regionName() {

    var client = ClientBuilder.newBuilder()
        .register(LOGGING)
        .register(Aws4AuthenticationFeature.class)
        .property("accessKey", getAccessKey())
        .property("secretKey", getSecretKey())
        .property("serviceName", "lex")
        .build();

    var response = client
        .target("https://runtime-v2-lex.eu-central-1.amazonaws.com")
        .path("/bots/{botId}/botAliases/{botAliasId}/botLocales/{localeId}/sessions/{sessionId}/text")
        .resolveTemplate("botId", "IMRTYQC6BN")
        .resolveTemplate("botAliasId", "GXHT5U6V6K")
        .resolveTemplate("sessionId", "10")
        .resolveTemplate("localeId", "en_US")
        .request()
        .post(Entity.entity("{\"text\":\"Book Hotel\"}", MediaType.APPLICATION_JSON));

    assertThat(response.getStatusInfo()).isEqualTo(Status.OK);
  }

  private Object getSecretKey() {
    var value = getPropertyOrEnv("AWS_SECRET_KEY");
    assertThat(value)
        .as("AWS secret key must be provided using system property or environment variable 'AWS_SECRET_KEY'")
        .isNotBlank();
    return value;
  }

  private Object getAccessKey() {
    var value = getPropertyOrEnv("AWS_ACCESS_KEY");
    assertThat(value)
        .as("AWS access key must be provided using system property or environment variable 'AWS_ACCESS_KEY'")
        .isNotBlank();
    return value;
  }

  private static String getPropertyOrEnv(String name) {
    var value = System.getProperty(name);
    if (value == null || value.isBlank()) {
      value = System.getenv(name);
    }
    return value;
  }
}