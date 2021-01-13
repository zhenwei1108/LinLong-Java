package org.sdk.crypto.symmetry;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.sdk.crypto.enums.SymmetryEnum;
import org.sdk.crypto.utils.Base64Util;


public class KeyTest {

  @Test
  public void genSm4KeyTest() throws NoSuchProviderException, NoSuchAlgorithmException {

    SecretKey secretKey = SymmetryKeyGenerator.genKey(SymmetryEnum.SM4);
    System.out.println("SM4对称密钥为:"+ Base64Util.encodeToString(secretKey.getEncoded()));
    System.out.println("密钥长度(字节)为:"+secretKey.getEncoded().length);
  }




}
