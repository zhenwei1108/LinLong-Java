package org.sdk.crypto.key.asymmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;
import java.util.Base64.Encoder;
import org.junit.jupiter.api.Test;


public class KeyPairTest {
  Encoder encoder = Base64.getEncoder();
  @Test
  public void genSm2KeyPairTest()
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
    KeyPair keyPair = SM2Key.genSm2KeyPair();
    System.out.println("SM2公钥为: "+encoder.encodeToString(keyPair.getPublic().getEncoded()));
    System.out.println("SM2私钥为: "+encoder.encodeToString(keyPair.getPrivate().getEncoded()));

  }

  @Test
  public void genRsaKeyPairTest() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPair keyPair = RSAKey.genRsa1024KeyPair();
    System.out.println("RSA公钥为: "+encoder.encodeToString(keyPair.getPublic().getEncoded()));
    System.out.println("RSA私钥为: "+encoder.encodeToString(keyPair.getPrivate().getEncoded()));
  }




}
