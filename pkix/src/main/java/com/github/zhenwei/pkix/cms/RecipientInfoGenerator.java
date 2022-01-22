package com.github.zhenwei.pkix.cms;

import cms.RecipientInfo;
import org.bouncycastle.operator.GenericKey;

public interface RecipientInfoGenerator
{
    RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException;
}