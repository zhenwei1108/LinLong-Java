package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Provider;
import java.security.Security;
import java.util.IdentityHashMap;
import java.util.Map;

public class WeGooBuilder {








  /**
   * @param []
   * @return void
   * @author zhangzhenwei
   * @description i will return something
   * @date 2022/2/3 16:33
   */
  public static void getInstance() throws WeGooCryptoException {
    new WeGooBuilder();
  }


  public WeGooBuilder() throws WeGooCryptoException {
    this(new WeGooProvider());
  }

  public WeGooBuilder(Provider provider) throws WeGooCryptoException {
    build(provider);
  }

  private void build(Provider provider) throws WeGooCryptoException {
    Security.addProvider(provider);
    if (provider instanceof WeGooProvider) {
      forceAuth(provider);
    }
  }


  /**
   * @param [provider]
   * @return void
   * @author zhangzhenwei
   * @description 强制认证, 自定义provider需要使用
   * CN=JCE Code Signing CA, OU=Java Software Code Signing, O=Oracle Corporation
   * 签名.
   * @date 2022/2/6 21:40
   */
  private void forceAuth(Provider provider) throws WeGooCryptoException {
    try {
      Map<Provider, Object> verificationResults = new IdentityHashMap<>();
      verificationResults.put(provider, true);
      Field field = Class.forName("javax.crypto.JceSecurity")
          .getDeclaredField("verificationResults");
      field.setAccessible(true);
      Field modifiers = field.getClass().getDeclaredField("modifiers");
      modifiers.setAccessible(true);
      modifiers.setInt(field, field.getModifiers() & ~Modifier.FINAL);
      field.set(verificationResults, verificationResults);
    } catch (Exception e) {
      throw new WeGooCryptoException(e);
    }
  }


}