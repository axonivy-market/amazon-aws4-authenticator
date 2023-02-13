# Amazon AWS4 Authenticator

This is a zero-dependency Java library to sign Jersey requests with a AWS4 signature.

## Maven

```xml
<repositories>
  <repository>
    <id>maven.axonivy.com</id>
    <url>https://maven.axonivy.com</url>
  </repository>
</repositories>

<dependencies>
  <dependency>
    <groupId>com.axonivy.connector.aws</groupId>
    <artifactId>amazon-aws4-authenticator</artifactId>
    <version>0.0.5</version>
  </dependency>
</dependencies>
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

## Restrictions

It is only possible to send `byte[]` or `json` as payload (see [ContentHasher](src/main/java/com/axonivy/connector/aws/authentication/ContentHasher.java)).
