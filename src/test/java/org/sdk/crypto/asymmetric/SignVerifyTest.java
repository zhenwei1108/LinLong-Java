package org.sdk.crypto.asymmetric;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import org.junit.jupiter.api.Test;
import org.sdk.crypto.utils.Base64Util;

public class SignVerifyTest {

  @Test
  public void sm2SignVerifyTest()
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException {
    KeyPair keyPair = AsymmetricKeyPairGenerator.genSm2KeyPair();
    byte[] data = "afadfwer234".getBytes(StandardCharsets.UTF_8);
    byte[] signData = AsymmetricSignVerify.sm2SignData(keyPair.getPrivate(), data);
    System.out.println("SM2签名值:"+ Base64Util.encodeToString(signData));
    boolean b = AsymmetricSignVerify.sm2VerifyData(keyPair.getPublic(), data, signData);
    System.out.println(b);
  }


}
