package com.github.zhenwei.pkix.cms;

import com.github.zhenwei.pkix.util.asn1.cmsRecipientInfo;
import  com.github.zhenwei.pkix.operator.GenericKey;

public interface RecipientInfoGenerator
{
    RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException;
}