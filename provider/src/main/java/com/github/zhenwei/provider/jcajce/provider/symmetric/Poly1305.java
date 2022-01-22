package com.github.zhenwei.provider.jcajce.provider.symmetric;

 
 
 
   (
 

public class Poly1305
{
    private Poly1305()
    {
    }

    public static class Mac
        extends BaseMac
    {
        public Mac()
        {
            super(new  Poly1305());
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Poly1305", 256, new Poly1305KeyGenerator());
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = Poly1305.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Mac.POLY1305", PREFIX + "$Mac");

            provider.addAlgorithm("KeyGenerator.POLY1305", PREFIX + "$KeyGen");
        }
    }
}