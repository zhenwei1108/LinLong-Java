package com.github.zhenwei.pkix.openssl.jcajce;

import com.github.zhenwei.core.asn1.pkcs.EncryptionScheme;
import com.github.zhenwei.core.asn1.pkcs.KeyDerivationFunc;
import com.github.zhenwei.core.asn1.pkcs.PBEParameter;
import com.github.zhenwei.core.asn1.pkcs.PBES2Parameters;
import com.github.zhenwei.core.asn1.pkcs.PBKDF2Params;
import com.github.zhenwei.core.asn1.pkcs.PKCS12PBEParams;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.CharToByteConverter;
import com.github.zhenwei.core.util.Strings;
import com.github.zhenwei.pkix.openssl.PEMException;
import com.github.zhenwei.pkix.operator.InputDecryptor;
import com.github.zhenwei.pkix.operator.InputDecryptorProvider;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.provider.jcajce.PBKDF1KeyWithParameters;
import com.github.zhenwei.provider.jcajce.PKCS12KeyWithParameters;
import com.github.zhenwei.provider.jcajce.io.CipherInputStream;
import com.github.zhenwei.provider.jcajce.util.DefaultJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.JcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.NamedJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.ProviderJcaJceHelper;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Provider;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * DecryptorProviderBuilder for producing DecryptorProvider for use with
 * PKCS8EncryptedPrivateKeyInfo.
 */
public class JceOpenSSLPKCS8DecryptorProviderBuilder {

  private JcaJceHelper helper;

  public JceOpenSSLPKCS8DecryptorProviderBuilder() {
    helper = new DefaultJcaJceHelper();
  }

  public JceOpenSSLPKCS8DecryptorProviderBuilder setProvider(String providerName) {
    helper = new NamedJcaJceHelper(providerName);

    return this;
  }

  public JceOpenSSLPKCS8DecryptorProviderBuilder setProvider(Provider provider) {
    helper = new ProviderJcaJceHelper(provider);

    return this;
  }

  public InputDecryptorProvider build(final char[] password)
      throws OperatorCreationException {
    return new InputDecryptorProvider() {
      public InputDecryptor get(final AlgorithmIdentifier algorithm)
          throws OperatorCreationException {
        final Cipher cipher;

        try {
          if (PEMUtilities.isPKCS5Scheme2(algorithm.getAlgorithm())) {
            PBES2Parameters params = PBES2Parameters.getInstance(algorithm.getParameters());
            KeyDerivationFunc func = params.getKeyDerivationFunc();
            EncryptionScheme scheme = params.getEncryptionScheme();
            PBKDF2Params defParams = (PBKDF2Params) func.getParameters();

            int iterationCount = defParams.getIterationCount().intValue();
            byte[] salt = defParams.getSalt();

            String oid = scheme.getAlgorithm().getId();

            SecretKey key;

            if (PEMUtilities.isHmacSHA1(defParams.getPrf())) {
              key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(helper, oid, password, salt,
                  iterationCount);
            } else {
              key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(helper, oid, password, salt,
                  iterationCount, defParams.getPrf());
            }

            cipher = helper.createCipher(oid);
            AlgorithmParameters algParams = helper.createAlgorithmParameters(oid);

            algParams.init(scheme.getParameters().toASN1Primitive().getEncoded());

            cipher.init(Cipher.DECRYPT_MODE, key, algParams);
          } else if (PEMUtilities.isPKCS12(algorithm.getAlgorithm())) {
            PKCS12PBEParams params = PKCS12PBEParams.getInstance(algorithm.getParameters());

            cipher = helper.createCipher(algorithm.getAlgorithm().getId());

            cipher.init(Cipher.DECRYPT_MODE, new PKCS12KeyWithParameters(password, params.getIV(),
                params.getIterations().intValue()));
          } else if (PEMUtilities.isPKCS5Scheme1(algorithm.getAlgorithm())) {
            PBEParameter params = PBEParameter.getInstance(algorithm.getParameters());

            cipher = helper.createCipher(algorithm.getAlgorithm().getId());

            cipher.init(Cipher.DECRYPT_MODE,
                new PBKDF1KeyWithParameters(password, new CharToByteConverter() {
                  public String getType() {
                    return "ASCII";
                  }

                  public byte[] convert(char[] password) {
                    return Strings.toByteArray(password);     // just drop hi-order byte.
                  }
                }, params.getSalt(), params.getIterationCount().intValue()));
          } else {
            throw new PEMException("Unknown algorithm: " + algorithm.getAlgorithm());
          }

          return new InputDecryptor() {
            public AlgorithmIdentifier getAlgorithmIdentifier() {
              return algorithm;
            }

            public InputStream getInputStream(InputStream encIn) {
              return new CipherInputStream(encIn, cipher);
            }
          };
        } catch (IOException e) {
          throw new OperatorCreationException(
              algorithm.getAlgorithm() + " not available: " + e.getMessage(), e);
        } catch (GeneralSecurityException e) {
          throw new OperatorCreationException(
              algorithm.getAlgorithm() + " not available: " + e.getMessage(), e);
        }
      }

      ;
    };
  }
}