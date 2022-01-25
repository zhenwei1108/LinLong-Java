package com.github.zhenwei.pkix.openssl.jcajce;

import com.github.zhenwei.pkix.openssl.PEMDecryptor;
import com.github.zhenwei.pkix.openssl.PEMDecryptorProvider;
import com.github.zhenwei.pkix.openssl.PEMException;
import com.github.zhenwei.pkix.openssl.PasswordException;
import com.github.zhenwei.provider.jcajce.util.DefaultJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.JcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.NamedJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.ProviderJcaJceHelper;
import java.security.Provider;

public class JcePEMDecryptorProviderBuilder {

  private JcaJceHelper helper = new DefaultJcaJceHelper();

  public JcePEMDecryptorProviderBuilder setProvider(Provider provider) {
    this.helper = new ProviderJcaJceHelper(provider);

    return this;
  }

  public JcePEMDecryptorProviderBuilder setProvider(String providerName) {
    this.helper = new NamedJcaJceHelper(providerName);

    return this;
  }

  public PEMDecryptorProvider build(final char[] password) {
    return new PEMDecryptorProvider() {
      public PEMDecryptor get(final String dekAlgName) {
        return new PEMDecryptor() {
          public byte[] decrypt(byte[] keyBytes, byte[] iv)
              throws PEMException {
            if (password == null) {
              throw new PasswordException("Password is null, but a password is required");
            }

            return PEMUtilities.crypt(false, helper, keyBytes, password, dekAlgName, iv);
          }
        };
      }
    };
  }
}