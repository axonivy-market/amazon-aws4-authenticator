package com.axonivy.connector.aws.authentication;

import javax.ws.rs.core.Feature;
import javax.ws.rs.core.FeatureContext;

/**
 * <p>A JAX-RS Feature that signs requests to call Amazon AWS API's like Amazon Lex.</p>
 * <p>The class implements Version 4 of the AWS signing.
 * See https://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html for details</p>
 * <p>To use this feature define the following properties:
 * <table>
 * <tr><th>Name</th><th>Description</th></tr>
 * <tr><td>accessKey</td><td>The access key of the Amazon IAM user that you want to use to call the service</td></tr>
 * <tr><td>secretKey</td><td>The secret key of the Amazon IAM user that you want to use to call the service</td></tr>
 * <tr><td>regionName</td><td>The Amazon region where you want to call the service. E.g. eu-central-1 for Frankfurt, us-west-1 for north california, ...</td></tr>
 * <tr><td>serviceName</td><td>The name of the Amazon service you want to call. E.g. iam for Amazon Identify and Access Management, lex for Amazon Lex,  ...</td></tr>
 * </table>
 * </p>
 * @author rwei
 * @since 06.08.2021
 */
public class Aws4AuthenticationFeature implements Feature {

  @Override
  public boolean configure(FeatureContext context) {
    context.register(Aws4AuthenticationRequestFilter.class);
    return true;
  }
}
