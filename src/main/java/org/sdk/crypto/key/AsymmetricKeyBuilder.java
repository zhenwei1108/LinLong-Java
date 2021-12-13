package org.sdk.crypto.key;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.sdk.crypto.init.InitProvider;

/**
 * @description: 非对称密钥生成
 * @date: 2021/6/1 23:15
 * {@link org.bouncycastle.jce.provider.BouncyCastleProvider#setup()}
 * BC默认实现在:
 * {@link org.bouncycastle.jcajce.provider.asymmetric}
 * 其中GM(国密?) 为EC的子类. 包含常见国产算法的使用方式.
 */
public class AsymmetricKeyBuilder {

  /**
   * @param [alg = 算法, len = 长度]
   * @return java.security.KeyPair
   * @description 产生非对称密钥. 常见算法:RSA,SM2
   * 详细算法见: {@link org.bouncycastle.jce.provider.BouncyCastleProvider#ASYMMETRIC_CIPHERS}
   * @date 2021/6/1 23:13
   */
  public static KeyPair genKeyPair(String alg, int len)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance(alg, InitProvider.BC_PROVIDER);
    generator.initialize(len);
    return generator.generateKeyPair();
  }


}