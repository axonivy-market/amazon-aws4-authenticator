package com.axonivy.connector.aws.authenticator;

import static org.assertj.core.api.Assertions.assertThat;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response.Status;

import org.junit.jupiter.api.Test;

import com.axonivy.connector.aws.authentication.Aws4AuthenticationFeature;

class TestAws4AuthenticatorFeature {

  @Test
  void authenticator_with_regionName() {

    var client = ClientBuilder.newBuilder()
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
    var value = System.getProperty("aws.secret.key");
    assertThat(value)
        .as("AWS secret key must be provided using system property 'aws.secret.key'")
        .isNotBlank();
    return value;
  }

  private Object getAccessKey() {
    var value = System.getProperty("aws.access.key");
    assertThat(value)
        .as("AWS access key must be provided using system property 'aws.access.key'")
        .isNotBlank();
    return value;
  }
}
