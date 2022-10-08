package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.ASN1Boolean;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.KeyPurposeId;
import com.github.zhenwei.core.enums.DigestAlgEnum;
import com.github.zhenwei.pkix.util.asn1.tsp.MessageImprint;
import com.github.zhenwei.pkix.util.asn1.tsp.TimeStampReq;
import java.math.BigInteger;

/**
 * @description: TimeStamp
 *  时间戳 RFC-3161
 * @author: zhangzhenwei
 * @since: 1.0.0
 * @date: 2022/2/28  10:48 下午
 */
public class TimeStampBuilder {

  public void generateTssRequest(DigestAlgEnum digestAlgEnum, byte[] digest,String nonce ){
    AlgorithmIdentifier identifier = new AlgorithmIdentifier(digestAlgEnum.getOid());
    MessageImprint messageImprint = new MessageImprint(identifier,digest);
    BigInteger bigIntegerNonce = new BigInteger(nonce);
    //todo 不太对
    ASN1Boolean certReq = ASN1Boolean.getInstance(ASN1Boolean.FALSE);
    TimeStampReq timeStampReq = new TimeStampReq(messageImprint,
        KeyPurposeId.id_kp_timeStamping.toOID(), new ASN1Integer(bigIntegerNonce), certReq, null);

  }


}
