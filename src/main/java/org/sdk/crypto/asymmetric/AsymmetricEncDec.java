package org.sdk.crypto.asymmetric;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.sdk.crypto.utils.Base64Util;

public class AsymmetricEncDec {


  public static void encData(byte[] data)
      throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    KeyPair keyPair = AsymmetricKeyPairGenerator.genRsa1024KeyPair();
    System.out.println(Base64Util.encodeToString(keyPair.getPrivate().getEncoded()));
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    cipher.update(data);
    byte[] bytes = cipher.doFinal();
    System.out.println(bytes.length);
    System.out.println(Base64Util.encodeToString(bytes));

  }


}
