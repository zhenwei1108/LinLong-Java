package com.github.zhenwei.provider.jcajce.provider.symmetric;

import com.github.zhenwei.core.crypto.CipherKeyGenerator;
import com.github.zhenwei.core.crypto.CryptoServicesRegistrar;
import com.github.zhenwei.core.crypto.engines.RC532Engine;
import com.github.zhenwei.core.crypto.engines.RC564Engine;
import com.github.zhenwei.core.crypto.macs.CBCBlockCipherMac;
import com.github.zhenwei.core.crypto.macs.CFBBlockCipherMac;
import com.github.zhenwei.core.crypto.modes.CBCBlockCipher;
import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.BaseBlockCipher;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.BaseMac;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import com.github.zhenwei.provider.jcajce.provider.util.AlgorithmProvider;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public final class RC5
{
    private RC5()
    {
    }

    /**
     * RC5
     */
    public static class ECB32
        extends BaseBlockCipher
    {
        public ECB32()
        {
            super(new RC532Engine());
        }
    }

    /**
     * RC564
     */
    public static class ECB64
        extends BaseBlockCipher
    {
        public ECB64()
        {
            super(new RC564Engine());
        }
    }

    public static class CBC32
       extends BaseBlockCipher
    {
        public CBC32()
        {
            super(new CBCBlockCipher(new RC532Engine()), 64);
        }
    }

    public static class KeyGen32
        extends BaseKeyGenerator
    {
        public KeyGen32()
        {
            super("RC5", 128, new CipherKeyGenerator());
        }
    }

    /**
     * RC5
     */
    public static class KeyGen64
        extends BaseKeyGenerator
    {
        public KeyGen64()
        {
            super("RC5-64", 256, new CipherKeyGenerator());
        }
    }

    public static class AlgParamGen
        extends BaseAlgorithmParameterGenerator
    {
        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for RC5 parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[] iv = new byte[8];

            if (random == null)
            {
                random = CryptoServicesRegistrar.getSecureRandom();
            }

            random.nextBytes(iv);

            AlgorithmParameters params;

            try
            {
                params = createParametersInstance("RC5");
                params.init(new IvParameterSpec(iv));
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.getMessage());
            }

            return params;
        }
    }

    public static class Mac32
        extends BaseMac
    {
        public Mac32()
        {
            super(new CBCBlockCipherMac(new RC532Engine()));
        }
    }

    public static class CFB8Mac32
        extends BaseMac
    {
        public CFB8Mac32()
        {
            super(new CFBBlockCipherMac(new RC532Engine()));
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "RC5 IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = RC5.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.RC5", PREFIX + "$ECB32");
            provider.addAlgorithm("Alg.Alias.Cipher.RC5-32", "RC5");
            provider.addAlgorithm("Cipher.RC5-64", PREFIX + "$ECB64");
            provider.addAlgorithm("KeyGenerator.RC5", PREFIX + "$KeyGen32");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.RC5-32", "RC5");
            provider.addAlgorithm("KeyGenerator.RC5-64", PREFIX + "$KeyGen64");
            provider.addAlgorithm("AlgorithmParameters.RC5", PREFIX + "$AlgParams");
            provider.addAlgorithm("AlgorithmParameters.RC5-64", PREFIX + "$AlgParams");
            provider.addAlgorithm("Mac.RC5MAC", PREFIX + "$Mac32");
            provider.addAlgorithm("Alg.Alias.Mac.RC5", "RC5MAC");
            provider.addAlgorithm("Mac.RC5MAC/CFB8", PREFIX + "$CFB8Mac32");
            provider.addAlgorithm("Alg.Alias.Mac.RC5/CFB8", "RC5MAC/CFB8");

        }
    }
}