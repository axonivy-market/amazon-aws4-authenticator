package com.axonivy.connector.aws.authentication;

import static com.axonivy.connector.aws.authentication.Constants.UTF8;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

class Crypto {

  private static final String SIGN_ALGORITHM = "HmacSHA256";
  private static final String HASH_ALGORITHM = "SHA-256";

  private Crypto() {}

  static String hash(String payload) throws NoSuchAlgorithmException {
    return hash(payload.getBytes(UTF8));
  }

  static String hash(byte[] payload) throws NoSuchAlgorithmException {
    var digest = MessageDigest.getInstance(HASH_ALGORITHM);
    var hash = digest.digest(payload);
    return Hex.encodeHexString(hash);
  }

  static byte[] hmac(String data, byte[] key) throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException {
    var mac = Mac.getInstance(SIGN_ALGORITHM);
    var keySpec = new SecretKeySpec(key, SIGN_ALGORITHM);
    mac.init(keySpec);
    return mac.doFinal(data.getBytes(UTF8));
  }
}
