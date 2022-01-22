package com.github.zhenwei.pkix.cms.bc;

import cms.KEKIdentifier;
import org.bouncycastle.cms.KEKRecipientInfoGenerator;
import org.bouncycastle.operator.bc.BcSymmetricKeyWrapper;

public class BcKEKRecipientInfoGenerator
    extends KEKRecipientInfoGenerator
{
    public BcKEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, BcSymmetricKeyWrapper kekWrapper)
    {
        super(kekIdentifier, kekWrapper);
    }

    public BcKEKRecipientInfoGenerator(byte[] keyIdentifier, BcSymmetricKeyWrapper kekWrapper)
    {
        this(new KEKIdentifier(keyIdentifier, null, null), kekWrapper);
    }
}