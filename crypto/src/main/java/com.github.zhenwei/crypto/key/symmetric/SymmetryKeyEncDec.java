package org.sdk.crypto.key.symmetric;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.sdk.crypto.enums.SymmetryCipherEnum;
import org.sdk.crypto.init.InitProvider;

public class SymmetryKeyEncDec extends InitProvider {

  /**
   * @description: 对称加密
   * @param: [symmetry, key, data]
   * @return: byte[]
   * @author zhangzhenwei
   * @date: 2021/1/13 1:39 下午
   */
  public static byte[] encData(SymmetryCipherEnum symmetry, SecretKey key, byte[] iv, byte[] data)
      throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
    Cipher cipher = Cipher.getInstance(symmetry.getCipherAlg(), BC_PROVIDER);
    if (iv != null && iv.length != 0) {
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
    } else {
      cipher.init(Cipher.ENCRYPT_MODE, key);
    }
    cipher.update(data);
    return cipher.doFinal();
  }

  /**
   * @description: 对称解密
   * @param: [symmetry, key, data]
   * @return: byte[]
   * @author zhangzhenwei
   * @date: 2021/1/13 1:40 下午
   */
  public static byte[] decData(SymmetryCipherEnum symmetry, SecretKey key, byte[] iv,
      byte[] encData)
      throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
    Cipher cipher = Cipher.getInstance(symmetry.getCipherAlg(), BC_PROVIDER);
    if (iv != null && iv.length != 0) {
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
    } else {
      cipher.init(Cipher.ENCRYPT_MODE, key);
    }
    cipher.update(encData);
    return cipher.doFinal();
  }


  public void encStreamData(SymmetryCipherEnum symmetry, SecretKey key, InputStream inputStream,
      OutputStream outputStream, int bufferLength, byte[] iv)
      throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
    Cipher cipher = Cipher.getInstance(symmetry.getCipherAlg(), BC_PROVIDER);
    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
    CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
    byte[] buffer = new byte[bufferLength];
    while (true) {
      int read = cipherInputStream.read(buffer);
      if (read == -1) {
        break;
      } else {
        outputStream.write(buffer);
      }
    }
    cipherInputStream.close();
    inputStream.close();
    outputStream.close();
  }


}