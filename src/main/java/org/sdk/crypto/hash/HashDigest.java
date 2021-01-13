package org.sdk.crypto.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.sdk.crypto.enums.DigestEnum;
import org.sdk.crypto.init.InitProvider;

public class HashDigest extends InitProvider {

  public static byte[] digest(DigestEnum hash, byte[] data)
      throws NoSuchProviderException, NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance(hash.name(), BC_PROVIDER);
    digest.update(data);
    return digest.digest();

  }



}
