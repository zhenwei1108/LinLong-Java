package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.provider.jce.provider.LinLongProvider;
import java.security.Security;

public class LinLongBuilder {


  public LinLongBuilder() {
    addProvider();
  }






  private void addProvider(){
    if (Security.getProvider(LinLongProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new LinLongProvider());
    }
  }

}