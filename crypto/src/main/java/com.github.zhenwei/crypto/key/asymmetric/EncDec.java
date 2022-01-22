package org.sdk.crypto.key.asymmetric;

import java.security.Key;
import javax.crypto.Cipher;
import org.sdk.crypto.exception.CryptoSDKException;
import org.sdk.crypto.exception.ErrorEnum;

public class EncDec {

  public static byte[] rsaEncDecData(boolean isEncrypt, Key key, byte[] data) {
    try {
      Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);
      cipher.update(data);
      return cipher.doFinal();
    } catch (Exception e) {
      throw new CryptoSDKException(ErrorEnum.RSA_ENC_DATA_ERROR, e);
    }
  }


}