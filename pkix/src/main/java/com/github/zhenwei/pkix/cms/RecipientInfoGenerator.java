package com.github.zhenwei.pkix.cms;

import cms.RecipientInfo;
import com.github.zhenwei.pkix.operator.GenericKey;


public interface RecipientInfoGenerator
{
    RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException;
}