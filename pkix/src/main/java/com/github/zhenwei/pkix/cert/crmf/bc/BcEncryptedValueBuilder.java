package com.github.zhenwei.pkix.cert.crmf.bc;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import com.github.zhenwei.pkix.util.asn1.crmf.EncryptedValue;
import com.github.zhenwei.pkix.cert.crmf.CRMFException;
import com.github.zhenwei.pkix.cert.crmf.EncryptedValueBuilder;
import com.github.zhenwei.pkix.cert.jcajce.JcaX509CertificateHolder;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.util.PrivateKeyInfoFactory;
import  com.github.zhenwei.pkix.operator.KeyWrapper;
import  com.github.zhenwei.pkix.operator.OutputEncryptor;

/**
 * Lightweight convenience class for EncryptedValueBuilder
 */
public class BcEncryptedValueBuilder
    extends EncryptedValueBuilder
{
    public BcEncryptedValueBuilder(KeyWrapper wrapper, OutputEncryptor encryptor)
    {
        super(wrapper, encryptor);
    }

    /**
     * Build an EncryptedValue structure containing the passed in certificate.
     *
     * @param certificate the certificate to be encrypted.
     * @return an EncryptedValue containing the encrypted certificate.
     * @throws CRMFException on a failure to encrypt the data, or wrap the symmetric key for this value.
     */
    public EncryptedValue build(X509Certificate certificate)
        throws CertificateEncodingException, CRMFException
    {
        return build(new JcaX509CertificateHolder(certificate));
    }

    /**
     * Build an EncryptedValue structure containing the private key details contained in
     * the passed PrivateKey.
     *
     * @param privateKey a private key parameter.
     * @return an EncryptedValue containing an EncryptedPrivateKeyInfo structure.
     * @throws CRMFException on a failure to encrypt the data, or wrap the symmetric key for this value.
     */
    public EncryptedValue build(AsymmetricKeyParameter privateKey)
        throws CRMFException, IOException
    {
        return build(PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey));
    }
}