package com.github.zhenwei.pkix.cms.bc;


import java.io.IOException;
 
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.bc.BcRSAAsymmetricKeyWrapper;

public class BcRSAKeyTransRecipientInfoGenerator
    extends BcKeyTransRecipientInfoGenerator
{
    public BcRSAKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, AlgorithmIdentifier encAlgId, AsymmetricKeyParameter publicKey)
    {
        super(subjectKeyIdentifier, new BcRSAAsymmetricKeyWrapper(encAlgId, publicKey));
    }

    public BcRSAKeyTransRecipientInfoGenerator(X509CertificateHolder recipientCert)
        throws IOException
    {
        super(recipientCert, new BcRSAAsymmetricKeyWrapper(recipientCert.getSubjectPublicKeyInfo().getAlgorithm(), recipientCert.getSubjectPublicKeyInfo()));
    }
}