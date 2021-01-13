package org.sdk.crypto.hash;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.junit.jupiter.api.Test;
import org.sdk.crypto.enums.DigestEnum;

public class HashTest {

  @Test
  public void sha1Test() throws NoSuchProviderException, NoSuchAlgorithmException {
    byte[] digest = HashDigest.digest(DigestEnum.SHA1, "adsf".getBytes());
    System.out.println(digest.length);
  }


}
