package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.provider.jce.provider.ChaosProvider;
import java.security.Security;

public class ChaosBuilder {


  public ChaosBuilder() {
    addProvider();
  }






  private void addProvider(){
    if (Security.getProvider(ChaosProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new ChaosProvider());
    }
  }

}