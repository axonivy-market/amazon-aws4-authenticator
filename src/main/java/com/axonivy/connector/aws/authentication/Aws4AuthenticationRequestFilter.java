package com.axonivy.connector.aws.authentication;

import static com.axonivy.connector.aws.authentication.Constants.X_AMZ_CONTENT;
import static com.axonivy.connector.aws.authentication.Constants.X_AMZ_DATE;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.ext.Providers;

/**
 * Request filter that signs requests to call Amazon AWS REST API.
 * @author rwei
 * @since 06.08.2021
 */
public class Aws4AuthenticationRequestFilter implements ClientRequestFilter {

  private static final String AUTHORIZATION = "Authorization";

  @Context
  private Providers providers;

  @Override
  public void filter(ClientRequestContext context) throws IOException {
    try {
      var signer = new Signer(context, providers);
      var headers = context.getHeaders();
      headers.add(X_AMZ_CONTENT, signer.contentHash());
      headers.add(X_AMZ_DATE, signer.getTimeStamp());
      headers.add(AUTHORIZATION, signer.sign());
    } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
      throw new IOException("Could not sign request", ex);
    }
  }
}
