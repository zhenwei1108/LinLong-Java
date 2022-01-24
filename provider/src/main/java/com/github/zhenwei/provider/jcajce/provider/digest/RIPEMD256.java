package com.github.zhenwei.provider.jcajce.provider.digest;

import com.github.zhenwei.core.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.github.zhenwei.core.crypto.CipherKeyGenerator;
import com.github.zhenwei.core.crypto.digests.RIPEMD256Digest;
import com.github.zhenwei.core.crypto.macs.HMac;
import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.BaseMac;

public class RIPEMD256
{
    private RIPEMD256()
    {

    }

    static public class Digest
        extends BCMessageDigest
        implements Cloneable
    {
        public Digest()
        {
            super(new RIPEMD256Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Digest d = (Digest)super.clone();
            d.digest = new RIPEMD256Digest((RIPEMD256Digest)digest);

            return d;
        }
    }

    /**
     * RIPEMD256 HMac
     */
    public static class HashMac
        extends BaseMac
    {
        public HashMac()
        {
            super(new HMac(new RIPEMD256Digest()));
        }
    }

    public static class KeyGenerator
        extends BaseKeyGenerator
    {
        public KeyGenerator()
        {
            super("HMACRIPEMD256", 256, new CipherKeyGenerator());
        }
    }

    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = RIPEMD256.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("MessageDigest.RIPEMD256", PREFIX + "$Digest");
            provider.addAlgorithm("Alg.Alias.MessageDigest." + TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD256");

            addHMACAlgorithm(provider, "RIPEMD256", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
        }
    }
}