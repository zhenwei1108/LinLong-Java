package org.sdk.crypto.key.asymmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import org.sdk.crypto.init.InitProvider;

public class SM2Key {

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
    //指定曲线
    AlgorithmParameterSpec spec = new ECGenParameterSpec("sm2p256v1");
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", InitProvider.BC_PROVIDER);
    generator.initialize(spec);
    return generator.generateKeyPair();
  }


}
