package com.github.zhenwei.pkix.cms;

import com.github.zhenwei.pkix.operator.GenericKey;
import com.github.zhenwei.pkix.util.asn1.cms.RecipientInfo;

public interface RecipientInfoGenerator {

  RecipientInfo generate(GenericKey contentEncryptionKey)
      throws CMSException;
}