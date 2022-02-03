package com.github.zhenwei.sdk.builder;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Provider;
import java.util.IdentityHashMap;
import java.util.Map;

public class WeGooBuilder {

  public void forceAuth(Provider provider) {
    try {
      Class<?> aClass = Class.forName("javax.crypto.JceSecurity");
      Map<Provider, Object> verificationResults = new IdentityHashMap<>();
      verificationResults.put(provider, true);
      Field field = aClass.getDeclaredField("verificationResults");
      field.setAccessible(true);
      Field modifiers = field.getClass().getDeclaredField("modifiers");
      modifiers.setAccessible(true);
      modifiers.setInt(field, field.getModifiers() & ~Modifier.FINAL);
      field.set(verificationResults, verificationResults);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }


}