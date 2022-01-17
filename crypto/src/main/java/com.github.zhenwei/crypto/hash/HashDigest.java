package org.sdk.crypto.hash;

import org.sdk.crypto.enums.DigestEnum;
import org.sdk.crypto.init.InitProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class HashDigest extends InitProvider {


  public static byte[] digest(DigestEnum hash, byte[] data)
      throws NoSuchProviderException, NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance(hash.name(), BC_PROVIDER);
    digest.update(data);
    return digest.digest();
  }

  public static byte[] digest(DigestEnum hash, byte[] data, byte[] publicKey)
          throws NoSuchProviderException, NoSuchAlgorithmException {
    //TODO SM3 需要公钥参与运算
    if (hash.isNeedPubKey()){
      MessageDigest digest = MessageDigest.getInstance(hash.name(), BC_PROVIDER);
      digest.update(data);
      return digest.digest();
    }
    return digest(hash,data);
  }

}
