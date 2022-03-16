package com.github.zhenwei.provider.jcajce.provider.keystore;

import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class JKS {

    private static final String PREFIX = "com.github.zhenwei.provider.jcajce.provider.keystore" + ".jks.";

    public static class Mappings extends AsymmetricAlgorithmProvider {

        public Mappings() {
        }

        /**
         * @param [provider]
         * @return void
         * @author zhangzhenwei
         * @description 借用Sun-Provider的实现
         * @date 2022/3/16  10:24 下午
         * @since: 1.0.0
         * @see sun.security.provider.Sun
         * {@link sun.security.provider.JavaKeyStore}
         */
        public void configure(ConfigurableProvider provider) {
            provider.addAlgorithm("KeyStore.JKS", PREFIX + "WeGooJavaKeyStore$DualFormatJKS");
        }
    }
}
