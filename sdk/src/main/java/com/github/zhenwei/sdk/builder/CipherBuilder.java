package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.sdk.enums.CipherAlgEnum;
import com.github.zhenwei.sdk.enums.exception.CipherExceptionMessageEnum;
import com.github.zhenwei.sdk.exception.WeGooCipherException;
import java.security.Key;
import java.security.Provider;
import javax.crypto.Cipher;

public class CipherBuilder {

  private Provider provider;

  public CipherBuilder(Provider provider) {
    this.provider = provider;
  }

  public byte[] cipher(CipherAlgEnum cipherAlgEnum, Key key, byte[] sourceData, boolean encrypt)
      throws WeGooCipherException {
    try {
      Cipher cipher = Cipher.getInstance(cipherAlgEnum.getAlg(), provider);
      cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);
      return cipher.doFinal(sourceData);
    } catch (Exception e) {
      throw new WeGooCipherException(CipherExceptionMessageEnum.cipher_data_err, e);
    }
  }

}