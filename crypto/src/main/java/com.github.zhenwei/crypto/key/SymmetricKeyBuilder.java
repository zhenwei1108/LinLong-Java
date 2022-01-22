package org.sdk.crypto.key;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.CipherKeyGenerator;

import org.sdk.crypto.init.InitProvider;

/**
 * @description: 对称密钥生成
 * 对称密钥加载方式见:
 * {@link BouncyCastleProvider#setup()}
 * 各种实现方式在如下包下
 * {@link org.bouncycastle.jcajce.provider.symmetric}
 * @date: 2021/6/1 23:07
 */
public class SymmetricKeyBuilder {


  /**
   * @param alg=算法 len=密钥长度
   * @return javax.crypto.SecretKey
   * @description 生成对称密钥, 实质为生成随机数 {@link CipherKeyGenerator#generateKey()}
   * @date 2021/6/1 22:59
   * 算法请参考:
   * {@link org.bouncycastle.jce.provider.BouncyCastleProvider#SYMMETRIC_CIPHERS}
   * 其中 DESede = 3DES
   */
  public static SecretKey genSymmetricSey(String alg, int len)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyGenerator generator = KeyGenerator.getInstance(alg, InitProvider.BC_PROVIDER);
    generator.init(len);
    return generator.generateKey();
  }


}