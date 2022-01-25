package com.github.zhenwei.pkix.cms.bc;

import com.github.zhenwei.pkix.cms.KEKRecipientInfoGenerator;
import com.github.zhenwei.pkix.operator.bc.BcSymmetricKeyWrapper;
import com.github.zhenwei.pkix.util.asn1.cms.KEKIdentifier;

public class BcKEKRecipientInfoGenerator
    extends KEKRecipientInfoGenerator {

  public BcKEKRecipientInfoGenerator(KEKIdentifier kekIdentifier,
      BcSymmetricKeyWrapper kekWrapper) {
    super(kekIdentifier, kekWrapper);
  }

  public BcKEKRecipientInfoGenerator(byte[] keyIdentifier, BcSymmetricKeyWrapper kekWrapper) {
    this(new KEKIdentifier(keyIdentifier, null, null), kekWrapper);
  }
}