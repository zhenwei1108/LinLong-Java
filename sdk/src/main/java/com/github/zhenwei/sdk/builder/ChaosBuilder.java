package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.provider.jce.provider.ChaosProvider;
import java.security.Provider;
import java.security.Security;

public class ChaosBuilder {


  private final Provider provider = new ChaosProvider();



  public ChaosBuilder() {
    addProvider();
  }






  private void addProvider(){
    if (Security.getProvider(ChaosProvider.PROVIDER_NAME) == null) {
      Security.addProvider(provider);
    }
  }

  public Provider getProvider() {
    return provider;
  }

}