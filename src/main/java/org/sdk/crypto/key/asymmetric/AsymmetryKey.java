package org.sdk.crypto.key.asymmetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import org.sdk.crypto.exception.CryptoSDKException;
import org.sdk.crypto.exception.ErrorEnum;
import org.sdk.crypto.init.InitProvider;

/**
 * @description: 非对称算法工具类
 * @date: 2021/6/5 23:02
 */
public class AsymmetryKey {


  /**
   * @param [asymmetryEnums]  {@link AsymmetryKeyEnums}
   * @return java.security.KeyPair
   * @description
   * 生成非对称密钥对  当前仅支持部分算法
   * RSA 算法见 {@link org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi}
   * SM2 算法见 {@link org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi}
   * ED25519 算法见 {@link org.bouncycastle.jcajce.provider.asymmetric.edec.KeyPairGeneratorSpi}
   *
   * @date 2021/6/5 23:04
   */
  public static KeyPair genKeyPair(AsymmetryKeyEnums asymmetryKeyEnums) throws CryptoSDKException {

    try {
      KeyPairGenerator generator = KeyPairGenerator
          .getInstance(asymmetryKeyEnums.getAlgName(), InitProvider.BC_PROVIDER);
      if (asymmetryKeyEnums == AsymmetryKeyEnums.SM2_256) {
        /**
         * sm2p256v1 为国密指定曲线
         * 其中order为n, n为G的阶. 使用随机数产生 d ∈ [1，n−2] (私钥)
         * 计算 P = [d]G = (x，y)
         *  (d，P)，其中d为私钥，P为公钥
         */
        generator.initialize(new ECGenParameterSpec("sm2p256v1"));
      } else {
        generator.initialize(asymmetryKeyEnums.getKeyLength());
      }
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new CryptoSDKException(ErrorEnum.GEN_KEYPAIR_ERROR, e);
    }
  }

}