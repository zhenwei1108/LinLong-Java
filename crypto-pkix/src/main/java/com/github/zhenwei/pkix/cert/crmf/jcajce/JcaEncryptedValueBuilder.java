package com.github.zhenwei.pkix.cert.crmf.jcajce;

import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.pkix.cert.crmf.CRMFException;
import com.github.zhenwei.pkix.cert.crmf.EncryptedValueBuilder;
import com.github.zhenwei.pkix.cert.jcajce.JcaX509CertificateHolder;
import com.github.zhenwei.pkix.operator.KeyWrapper;
import com.github.zhenwei.pkix.operator.OutputEncryptor;
import com.github.zhenwei.pkix.util.asn1.crmf.EncryptedValue;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * JCA convenience class for EncryptedValueBuilder
 */
public class JcaEncryptedValueBuilder
    extends EncryptedValueBuilder {

  public JcaEncryptedValueBuilder(KeyWrapper wrapper, OutputEncryptor encryptor) {
    super(wrapper, encryptor);
  }

  /**
   * Build an EncryptedValue structure containing the passed in certificate.
   *
   * @param certificate the certificate to be encrypted.
   * @return an EncryptedValue containing the encrypted certificate.
   * @throws CRMFException on a failure to encrypt the data, or wrap the symmetric key for this
   *                       value.
   */
  public EncryptedValue build(X509Certificate certificate)
      throws CertificateEncodingException, CRMFException {
    return build(new JcaX509CertificateHolder(certificate));
  }

  /**
   * Build an EncryptedValue structure containing the private key details contained in the passed
   * PrivateKey.
   *
   * @param privateKey the asymmetric private key.
   * @return an EncryptedValue containing an EncryptedPrivateKeyInfo structure.
   * @throws CRMFException on a failure to encrypt the data, or wrap the symmetric key for this
   *                       value.
   */
  public EncryptedValue build(PrivateKey privateKey)
      throws CertificateEncodingException, CRMFException {
    return build(PrivateKeyInfo.getInstance(privateKey.getEncoded()));
  }
}