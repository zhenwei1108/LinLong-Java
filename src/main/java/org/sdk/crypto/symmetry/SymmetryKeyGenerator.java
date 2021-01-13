package org.sdk.crypto.symmetry;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.sdk.crypto.enums.SymmetryEnum;
import org.sdk.crypto.init.InitProvider;

/**
 * @description: 构造对称密钥
 * @author zhangzhenwei
 * @date 2021/1/13 10:15 上午
 */
public class SymmetryKeyGenerator extends InitProvider {


  public static SecretKey genKey(SymmetryEnum algType)
      throws NoSuchProviderException, NoSuchAlgorithmException {
    KeyGenerator generator = KeyGenerator.getInstance(algType.name(), BC_PROVIDER);
    generator.init(algType.getKeyLength());
    return generator.generateKey();

  }


}
