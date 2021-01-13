package org.sdk.crypto.asymmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.sdk.crypto.init.InitProvider;

public class AsymmetricKeyPairGenerator extends InitProvider {

  /**
   * @description: 产生SM2密钥对 国密算法
   * @see org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator
   * @see org.bouncycastle.crypto.ec.CustomNamedCurves
   *
   * sm2p256v1 为国密指定曲线
   * 其中order为n, n为G的阶. 使用随机数产生 d ∈ [1，n−2] (私钥)
   * 计算 P = [d]G = (x，y)
   *  (d，P)，其中d为私钥，P为公钥
   *
   * @param: []
   * @return: java.security.KeyPair
   * @author zhangzhenwei
   * @date: 2021/1/4 5:03 下午
   */
  public static KeyPair genSm2KeyPair()
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {

    AlgorithmParameterSpec spec = new ECGenParameterSpec("sm2p256v1");
    //两步操作等价
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BC_PROVIDER);
    //同上一步等价
    Security.addProvider(new BouncyCastleProvider());
    generator = KeyPairGenerator.getInstance("EC", BC_PROVIDER);

    generator.initialize(spec);
    KeyPair keyPair = generator.generateKeyPair();
    return keyPair;
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
  public static KeyPair genRsa1024KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BC_PROVIDER);
    generator.initialize(1024);
    return generator.generateKeyPair();
  }


}
