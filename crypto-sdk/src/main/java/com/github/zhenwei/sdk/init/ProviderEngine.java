package com.github.zhenwei.sdk.init;

import com.github.zhenwei.provider.jce.provider.WeGooProvider;

import java.security.Provider;

public class ProviderEngine {

    private static volatile Provider provider = new WeGooProvider();

    public static void init(Provider newProvider){
        if (newProvider == null){
            synchronized (ProviderEngine.class){
                if (provider == null){
                    provider = newProvider;
                }
            }
        }
    }

    public static Provider getProvider(){
        return provider;
    }


}
