package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.sdk.enums.CipherAlgEnum;
import com.github.zhenwei.sdk.enums.exception.CipherExceptionMessageEnum;
import com.github.zhenwei.sdk.exception.WeGooCipherException;
import java.security.Key;
import java.security.Provider;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

/**
 * @description: 加解密实现
 * @author: zhangzhenwei
 * @since 1.0.0
 * @date: 2022/2/16 22:41
 */
public class CipherBuilder {

  private final Provider provider;

  public CipherBuilder(Provider provider) {
    this.provider = provider;
  }

  public byte[] cipher(CipherAlgEnum cipherAlgEnum, Key key, byte[] sourceData,
      IvParameterSpec ivParameterSpec, boolean encrypt) throws WeGooCipherException {
    try {
      Cipher cipher = Cipher.getInstance(cipherAlgEnum.getAlg(), provider);
      //如果
      if (cipherAlgEnum.getModeEnum().isNeedIV()) {
        if (ivParameterSpec == null) {
          throw new WeGooCipherException(CipherExceptionMessageEnum.iv_param_empty_err);
        }
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, ivParameterSpec);
      } else {
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);
      }
      return cipher.doFinal(sourceData);
    } catch (WeGooCipherException e) {
      throw e;
    } catch (Exception e) {
      throw new WeGooCipherException(CipherExceptionMessageEnum.cipher_data_err, e);
    }
  }

}