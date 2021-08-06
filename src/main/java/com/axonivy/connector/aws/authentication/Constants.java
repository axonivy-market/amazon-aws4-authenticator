package com.axonivy.connector.aws.authentication;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

interface Constants {
  static final String X_AMZ_DATE = "x-amz-date";
  static final String SIGNED_HEADERS = "host;" + X_AMZ_DATE;
  static final Charset UTF8 = StandardCharsets.UTF_8;
}
