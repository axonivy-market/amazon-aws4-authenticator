package com.axonivy.connector.aws.authenticator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.logging.LoggingFeature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockserver.integration.ClientAndServer;

import com.axonivy.connector.aws.authentication.Aws4AuthenticationFeature;

import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response.Status;

class TestAws4AuthenticatorFeature {

  private static final String ACCESS_KEY = "test-access-key";
  private static final String SECRET_KEY = "test-secret-key";
  private static final String LEX_RUNTIME = "http://runtime-v2-lex.eu-central-1.amazonaws.com";
  private static final String RECOGNIZE_TEXT_PATH = "/bots/IMRTYQC6BN/botAliases/GXHT5U6V6K/botLocales/en_US/sessions/10/text";
  private static final String RECOGNIZE_TEXT_REQUEST = "{\"text\":\"Book Hotel\"}";

  private static final Logger LOGGER = Logger.getLogger(TestAws4AuthenticatorFeature.class.getName());
  private static final LoggingFeature LOGGING = new LoggingFeature(
      LOGGER,
      Level.INFO,
      LoggingFeature.Verbosity.PAYLOAD_ANY,
      8192);

  private ClientAndServer mockServer;

  @BeforeEach
  void startMockServer() {
    mockServer = ClientAndServer.startClientAndServer(0);
    mockServer
        .when(request()
            .withMethod("POST")
            .withPath(RECOGNIZE_TEXT_PATH)
            .withBody(RECOGNIZE_TEXT_REQUEST))
        .respond(response()
            .withStatusCode(Status.OK.getStatusCode())
            .withHeader("Content-Type", MediaType.APPLICATION_JSON)
            .withBody("""
                {
                  "messages": [
                    {
                      "content": "Hotel booked",
                      "contentType": "PlainText"
                    }
                  ],
                  "sessionState": {
                    "dialogAction": {
                      "type": "Close"
                    },
                    "intent": {
                      "name": "BookHotel",
                      "state": "Fulfilled"
                    }
                  }
                }
                """));
  }

  @AfterEach
  void stopMockServer() {
    mockServer.stop();
  }

  @Test
  void authenticator_with_regionName() {

    var client = ClientBuilder.newBuilder()
        .register(LOGGING)
        .register(Aws4AuthenticationFeature.class)
        .property("accessKey", ACCESS_KEY)
        .property("secretKey", SECRET_KEY)
        .property("regionName", "eu-central-1")
        .property("serviceName", "lex")
        .property(ClientProperties.PROXY_URI, mockServerUrl())
        .build();

    var response = client
        .target(LEX_RUNTIME)
        .path("/bots/{botId}/botAliases/{botAliasId}/botLocales/{localeId}/sessions/{sessionId}/text")
        .resolveTemplate("botId", "IMRTYQC6BN")
        .resolveTemplate("botAliasId", "GXHT5U6V6K")
        .resolveTemplate("sessionId", "10")
        .resolveTemplate("localeId", "en_US")
        .request()
        .post(Entity.entity(RECOGNIZE_TEXT_REQUEST, MediaType.APPLICATION_JSON));

    assertThat(response.getStatusInfo()).isEqualTo(Status.OK);
    mockServer.verify(request()
        .withMethod("POST")
        .withPath(RECOGNIZE_TEXT_PATH)
        .withHeader("Authorization", "AWS4-HMAC-SHA256 Credential=" + ACCESS_KEY + "/.*")
        .withHeader("x-amz-date", ".+")
        .withHeader("x-amz-content-sha256", ".+"));
  }

  @Test
  void authenticator_without_regionName() {

    var client = ClientBuilder.newBuilder()
        .register(LOGGING)
        .register(Aws4AuthenticationFeature.class)
        .property("accessKey", ACCESS_KEY)
        .property("secretKey", SECRET_KEY)
        .property("serviceName", "lex")
        .property(ClientProperties.PROXY_URI, mockServerUrl())
        .build();

    var response = client
        .target(LEX_RUNTIME)
        .path("/bots/{botId}/botAliases/{botAliasId}/botLocales/{localeId}/sessions/{sessionId}/text")
        .resolveTemplate("botId", "IMRTYQC6BN")
        .resolveTemplate("botAliasId", "GXHT5U6V6K")
        .resolveTemplate("sessionId", "10")
        .resolveTemplate("localeId", "en_US")
        .request()
        .post(Entity.entity(RECOGNIZE_TEXT_REQUEST, MediaType.APPLICATION_JSON));

    assertThat(response.getStatusInfo()).isEqualTo(Status.OK);
    mockServer.verify(request()
        .withMethod("POST")
        .withPath(RECOGNIZE_TEXT_PATH)
        .withHeader("Authorization", "AWS4-HMAC-SHA256 Credential=" + ACCESS_KEY + "/.*")
        .withHeader("x-amz-date", ".+")
        .withHeader("x-amz-content-sha256", ".+"));
  }

  private String mockServerUrl() {
    return "http://localhost:" + mockServer.getLocalPort();
  }
}
