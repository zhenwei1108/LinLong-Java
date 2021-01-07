package org.sdk.crypto.asymmetric;

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
    KeyPair keyPair = GenKeyPair.genSm2KeyPair();
    System.out.println("SM2公钥为: "+encoder.encodeToString(keyPair.getPublic().getEncoded()));
    System.out.println("SM2私钥为: "+encoder.encodeToString(keyPair.getPrivate().getEncoded()));

  }

  @Test
  public void genRsaKeyPairTest() throws NoSuchAlgorithmException {
    KeyPair keyPair = GenKeyPair.genRsa1024KeyPair();
    System.out.println("RSA公钥为: "+encoder.encodeToString(keyPair.getPublic().getEncoded()));
    System.out.println("RSA私钥为: "+encoder.encodeToString(keyPair.getPrivate().getEncoded()));
  }




}
