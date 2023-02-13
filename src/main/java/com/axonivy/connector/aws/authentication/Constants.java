package com.axonivy.connector.aws.authentication;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

interface Constants {
  String X_AMZ_DATE = "x-amz-date";
  String SIGNED_HEADERS = "host;" + X_AMZ_DATE;
  Charset UTF8 = StandardCharsets.UTF_8;
}
