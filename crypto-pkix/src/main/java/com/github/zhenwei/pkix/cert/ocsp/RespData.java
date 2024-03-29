package com.github.zhenwei.pkix.cert.ocsp;

import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ocsp.ResponseData;
import com.github.zhenwei.core.asn1.ocsp.SingleResponse;
import com.github.zhenwei.core.asn1.x509.Extensions;
import java.util.Date;

/**
 * OCSP RFC 2560, RFC 6960
 * <pre>
 * ResponseData ::= SEQUENCE {
 *     version              [0] EXPLICIT Version DEFAULT v1,
 *     responderID              ResponderID,
 *     producedAt               GeneralizedTime,
 *     responses                SEQUENCE OF SingleResponse,
 *     responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 * </pre>
 */
public class RespData {

  private ResponseData data;

  public RespData(
      ResponseData data) {
    this.data = data;
  }

  public int getVersion() {
    return data.getVersion().intValueExact() + 1;
  }

  public RespID getResponderId() {
    return new RespID(data.getResponderID());
  }

  public Date getProducedAt() {
    return OCSPUtils.extractDate(data.getProducedAt());
  }

  public SingleResp[] getResponses() {
    ASN1Sequence s = data.getResponses();
    SingleResp[] rs = new SingleResp[s.size()];

    for (int i = 0; i != rs.length; i++) {
      rs[i] = new SingleResp(SingleResponse.getInstance(s.getObjectAt(i)));
    }

    return rs;
  }

  public Extensions getResponseExtensions() {
    return data.getResponseExtensions();
  }
}