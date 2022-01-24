package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;

/**
 * <pre>
 *     SymmRecipientInfo ::= SEQUENCE {
 *         recipientId HashedId8,
 *         encKey SymmetricCiphertext
 *     }
 * </pre>
 */
public class SymmRecipientInfo
    extends ASN1Object
{

    private final HashedId recipientId;
    private final SymmetricCiphertext encKey;

    public SymmRecipientInfo(HashedId recipientId, SymmetricCiphertext encKey)
    {
        this.recipientId = recipientId;
        this.encKey = encKey;
    }

    public HashedId getRecipientId()
    {
        return recipientId;
    }

    public SymmetricCiphertext getEncKey()
    {
        return encKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(recipientId, encKey);
    }
}