package org.sdk.crypto.key;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class KeyBuilder {


  public static PublicKey buildByteToKey(String alg, byte[] key)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory factory = KeyFactory.getInstance(alg);
    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
    PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);
    return publicKey;
  }

}
