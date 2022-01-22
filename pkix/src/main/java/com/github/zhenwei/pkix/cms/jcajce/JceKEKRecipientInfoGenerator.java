package com.github.zhenwei.pkix.cms.jcajce;

import cms.KEKIdentifier;
import java.security.Provider;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import org.bouncycastle.cms.KEKRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JceSymmetricKeyWrapper;

public class JceKEKRecipientInfoGenerator
    extends KEKRecipientInfoGenerator
{
    public JceKEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, SecretKey keyEncryptionKey)
    {
        super(kekIdentifier, new JceSymmetricKeyWrapper(keyEncryptionKey));
    }

    public JceKEKRecipientInfoGenerator(byte[] keyIdentifier, SecretKey keyEncryptionKey)
    {
        this(new KEKIdentifier(keyIdentifier, null, null), keyEncryptionKey);
    }

    public org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator setProvider(Provider provider)
    {
        ((JceSymmetricKeyWrapper)this.wrapper).setProvider(provider);

        return this;
    }

    public org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator setProvider(String providerName)
    {
        ((JceSymmetricKeyWrapper)this.wrapper).setProvider(providerName);

        return this;
    }

    public org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator setSecureRandom(SecureRandom random)
    {
        ((JceSymmetricKeyWrapper)this.wrapper).setSecureRandom(random);

        return this;
    }
}