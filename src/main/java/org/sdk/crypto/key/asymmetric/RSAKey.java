package org.sdk.crypto.key.asymmetric;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.sdk.crypto.init.InitProvider;

public class RSAKey {


  public static byte[] encData(byte[] data, PublicKey publicKey)
      throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    cipher.update(data);
    return cipher.doFinal();
  }

  /**
   * @description: 产生RSA密钥对 1024
   *  RSA 国际常用算法
   *  安全性和密钥模长直接相关 常见模长 1024,2048
   * @param: []
   * @return: java.security.KeyPair
   * @author zhangzhenwei
   * @date: 2021/1/6 9:08 下午
   */
  public static KeyPair genRsa1024KeyPair()
      throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", InitProvider.BC_PROVIDER);
    generator.initialize(1024);
    return generator.generateKeyPair();
  }

}
