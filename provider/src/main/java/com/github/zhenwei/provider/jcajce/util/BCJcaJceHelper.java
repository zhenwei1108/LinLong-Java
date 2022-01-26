package com.github.zhenwei.provider.jcajce.util;

import com.github.zhenwei.provider.jce.provider.LinLongProvider;
import java.security.Provider;
import java.security.Security;

/**
 * A JCA/JCE helper that refers to the BC provider for all it's needs.
 */
public class BCJcaJceHelper
    extends ProviderJcaJceHelper {

  private static volatile Provider bcProvider;

  private static synchronized Provider getBouncyCastleProvider() {
    final Provider system = Security.getProvider("LL");
    // Avoid using the old, deprecated system BC provider on Android.
    // See: https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html
    if (system instanceof LinLongProvider) {
      return system;
    } else if (bcProvider != null) {
      return bcProvider;
    } else {
      bcProvider = new LinLongProvider();

      return bcProvider;
    }
  }

  public BCJcaJceHelper() {
    super(getBouncyCastleProvider());
  }
}