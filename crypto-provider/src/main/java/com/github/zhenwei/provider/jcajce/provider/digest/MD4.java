package com.github.zhenwei.provider.jcajce.provider.digest;

import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.crypto.CipherKeyGenerator;
import com.github.zhenwei.core.crypto.digests.MD4Digest;
import com.github.zhenwei.core.crypto.macs.HMac;
import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.BaseMac;

public class MD4 {

  private MD4() {

  }

  /**
   * MD4 HashMac
   */
  public static class HashMac
      extends BaseMac {

    public HashMac() {
      super(new HMac(new MD4Digest()));
    }
  }

  public static class KeyGenerator
      extends BaseKeyGenerator {

    public KeyGenerator() {
      super("HMACMD4", 128, new CipherKeyGenerator());
    }
  }

  static public class Digest
      extends BCMessageDigest
      implements Cloneable {

    public Digest() {
      super(new MD4Digest());
    }

    public Object clone()
        throws CloneNotSupportedException {
      Digest d = (Digest) super.clone();
      d.digest = new MD4Digest((MD4Digest) digest);

      return d;
    }
  }

  public static class Mappings
      extends DigestAlgorithmProvider {

    private static final String PREFIX = MD4.class.getName();

    public Mappings() {
    }

    public void configure(ConfigurableProvider provider) {
      provider.addAlgorithm("MessageDigest.MD4", PREFIX + "$Digest");
      provider.addAlgorithm("Alg.Alias.MessageDigest." + PKCSObjectIdentifiers.md4, "MD4");

      addHMACAlgorithm(provider, "MD4", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
    }
  }
}