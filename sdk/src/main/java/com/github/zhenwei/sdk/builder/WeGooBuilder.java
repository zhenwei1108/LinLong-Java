package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import java.security.Provider;
import java.security.Security;

public class WeGooBuilder {


  private static final Provider provider = new WeGooProvider();



  public WeGooBuilder() {
    addProvider();
  }






  private void addProvider(){
    if (Security.getProvider(WeGooProvider.PROVIDER_NAME) == null) {
      Security.addProvider(provider);
    }
  }

  public static Provider getProvider() {
    return provider;
  }

}