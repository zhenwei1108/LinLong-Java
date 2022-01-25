package com.github.zhenwei.pkix.dvcs;

import com.github.zhenwei.pkix.util.asn1.dvcs.DVCSRequestInformationBuilder;
import com.github.zhenwei.pkix.util.asn1.dvcs.Data;
import com.github.zhenwei.pkix.util.asn1.dvcs.ServiceType;

/**
 * Builder of CCPD requests (Certify Claim of Possession of Data).
 */
public class CCPDRequestBuilder
    extends DVCSRequestBuilder {

  public CCPDRequestBuilder() {
    super(new DVCSRequestInformationBuilder(ServiceType.CCPD));
  }

  /**
   * Builds CCPD request.
   *
   * @param messageImprint - the message imprint to include.
   * @return a new DVCSRequest based on the state of this builder.
   * @throws DVCSException if an issue occurs during construction.
   */
  public DVCSRequest build(MessageImprint messageImprint)
      throws DVCSException {
    Data data = new Data(messageImprint.toASN1Structure());

    return createDVCRequest(data);
  }
}