# Amazon AWS4 Authenticator

This is a zero-dependency Java library to sign Jersey requests with a AWS4 signature.

## Maven

```xml
<dependency>
  <groupId>com.axonivy.connector.aws</groupId>
  <artifactId>amazon-aws4-authenticator</artifactId>
  <version>0.0.4</version>
</dependency>
```

## Usage

```java
var client = ClientBuilder.newClient()
  .register(new Aws4AuthenticationFeature())  
  .property("accessKey", "YOUR-ACCESS-KEY")
  .property("secretKey", "YOUR-SECRET-KEY")
  .property("regionName", "us-east-1")
  .property("serviceName", "s3");
```
