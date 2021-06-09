package org.sdk.crypto.key.symmetric;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.sdk.crypto.exception.CryptoSDKException;
import org.sdk.crypto.exception.ErrorEnum;
import org.sdk.crypto.init.InitProvider;

public class SymmetryKey {

  /**
   * @param [enums]
   * @return javax.crypto.SecretKey
   * @author zhangzhenwei@bjca.org.cn
   * @description 对称密钥生成实际为随机数. 各自差异于随机数发生器
   * @see java.security.SecureRandom
   *
   * DES算法长度限制
   * {@link org.bouncycastle.crypto.generators.DESKeyGenerator#init(KeyGenerationParameters)}
   * 3DES算法限制
   * {@link org.bouncycastle.crypto.generators.DESedeKeyGenerator#init(KeyGenerationParameters)}
   *
   * @date 2021/6/9 22:14
   */
  public static SecretKey genKey(SymmetryKeyEnums enums) {
    try {
      KeyGenerator generator = KeyGenerator.getInstance(enums.getAlg(), InitProvider.BC_PROVIDER);
      generator.init(enums.getLength());
      return generator.generateKey();
    } catch (Exception e) {
      throw new CryptoSDKException(ErrorEnum.GEN_KEY_ERROR, e);
    }
  }

}
