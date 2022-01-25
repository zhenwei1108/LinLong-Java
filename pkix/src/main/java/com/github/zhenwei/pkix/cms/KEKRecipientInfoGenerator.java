package com.github.zhenwei.pkix.cms;

import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.pkix.util.asn1.cms.KEKIdentifier;
import com.github.zhenwei.pkix.util.asn1.cms.KEKRecipientInfo;
import com.github.zhenwei.pkix.util.asn1.cms.RecipientInfo;
import  com.github.zhenwei.pkix.operator.GenericKey;
import  com.github.zhenwei.pkix.operator.OperatorException;
import  com.github.zhenwei.pkix.operator.SymmetricKeyWrapper;

public abstract class KEKRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    private final KEKIdentifier kekIdentifier;

    protected final SymmetricKeyWrapper wrapper;

    protected KEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, SymmetricKeyWrapper wrapper)
    {
        this.kekIdentifier = kekIdentifier;
        this.wrapper = wrapper;
    }

    public final RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException
    {
        try
        {
            ASN1OctetString encryptedKey = new DEROctetString(wrapper.generateWrappedKey(contentEncryptionKey));

            return new RecipientInfo(new KEKRecipientInfo(kekIdentifier, wrapper.getAlgorithmIdentifier(), encryptedKey));
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception wrapping content key: " + e.getMessage(), e);
        }
    }
}