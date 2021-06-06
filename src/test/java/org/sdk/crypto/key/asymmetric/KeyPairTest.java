package org.sdk.crypto.key.asymmetric;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Base64.Encoder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.sdk.crypto.init.InitProvider;


public class KeyPairTest {

  Encoder encoder = Base64.getEncoder();

  @BeforeAll
  public static void before(){
    InitProvider.init();
  }

  @Test
  public void genSm2KeyPairTest() {
    KeyPair keyPair = Asymmetry.genKeyPair(AsymmetryKeyEnums.SM2_256);
    System.out.println("SM2公钥为: " + encoder.encodeToString(keyPair.getPublic().getEncoded()));
    System.out.println("SM2私钥为: " + encoder.encodeToString(keyPair.getPrivate().getEncoded()));
  }

  @Test
  public void genED25519KeyPairTest() {
    KeyPair keyPair = Asymmetry.genKeyPair(AsymmetryKeyEnums.ED25519_256);
    System.out.println("ED25519公钥为: " + encoder.encodeToString(keyPair.getPublic().getEncoded()));
    System.out.println("ED25519私钥为: " + encoder.encodeToString(keyPair.getPrivate().getEncoded()));
  }


  @Test
  public void genRsaKeyPairTest()  {
    KeyPair keyPair = Asymmetry.genKeyPair(AsymmetryKeyEnums.RSA_1024);
    RSAPublicKey aPublic = (RSAPublicKey) keyPair.getPublic();
    BigInteger modulus = aPublic.getModulus();
    System.out.println(modulus);
    BigInteger publicExponent = aPublic.getPublicExponent();
    System.out.println(publicExponent);
    System.out.println("RSA公钥为: " + encoder.encodeToString(keyPair.getPublic().getEncoded()));
    System.out.println("RSA私钥为: " + encoder.encodeToString(keyPair.getPrivate().getEncoded()));
  }


}
