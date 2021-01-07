package org.sdk.crypto.asymmetric;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import org.junit.jupiter.api.Test;

public class SignVerifyTest {

  @Test
  public void sm2SignVerifyTest()
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException {
    KeyPair keyPair = GenKeyPair.genSm2KeyPair();
    byte[] data = "afadfwer234".getBytes(StandardCharsets.UTF_8);
    byte[] signData = SignVerify.sm2SignData(keyPair.getPrivate(), data);
    boolean b = SignVerify.sm2VerifyData(keyPair.getPublic(), data, signData);
    System.out.println(b);
  }


}
