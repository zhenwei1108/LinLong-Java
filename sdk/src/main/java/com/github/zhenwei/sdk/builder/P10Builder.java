package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.DERSet;
import com.github.zhenwei.core.asn1.pkcs.Attribute;
import com.github.zhenwei.core.asn1.pkcs.CertificationRequestInfo;
import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.pkix.operator.bc.BcContentSignerBuilder;
import com.github.zhenwei.pkix.operator.bc.BcECContentSignerBuilder;
import com.github.zhenwei.pkix.operator.bc.BcRSAContentSignerBuilder;
import com.github.zhenwei.pkix.pkcs.PKCS10CertificationRequest;
import com.github.zhenwei.pkix.pkcs.PKCS10CertificationRequestBuilder;
import com.github.zhenwei.sdk.builder.params.CertExtension;
import com.github.zhenwei.sdk.builder.params.CodingType;
import com.github.zhenwei.sdk.enums.DigestAlgEnum;
import com.github.zhenwei.sdk.enums.SignAlgEnum;
import com.github.zhenwei.sdk.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;
import com.github.zhenwei.sdk.util.Base64Util;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

/**
 * @author: zhangzhenwei
 * @description: P10Builder 参考RFC-2986  / GMT-0092
 * @since: 1.0.0
 * @date: 2022/2/21 10:16 下午
 */
public class P10Builder {

    private PKCS10CertificationRequest request;

    public P10Builder(byte[] data) throws WeGooCryptoException {
        try {
            request = new PKCS10CertificationRequest(data);
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.parse_p10_err);
        }
    }

    public String getSubjectDN() throws IOException {
        return request.getSubject().toString();
    }

    public PublicKey getPublicKey() {
        return (PublicKey) request.getSubjectPublicKeyInfo();
    }

    public String getP10() throws WeGooCryptoException {
        try {
            return Base64Util.encode(request.getEncoded());
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.encode_err, e);
        }
    }


    /**
     * @param [dn, publicKey, privateKey, list]
     *             主题项, 公钥, 私钥, 扩展项
     * @author zhangzhenwei
     * @description P10Builder
     * @since: 1.0.0
     * @date 2022/2/21 10:28 下午
     */
    public P10Builder(String dn, PublicKey publicKey, PrivateKey privateKey, List<CertExtension> list) throws WeGooCryptoException, OperatorCreationException {

        X500Name name = new X500Name(dn);
        ASN1Set set = ASN1Set.getInstance(parseExtension(list));
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(publicKey);
        // 主题, 公钥, 扩展项
        CertificationRequestInfo requestInfo = new CertificationRequestInfo(name, keyInfo, set);

        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(name, keyInfo);
        String algorithm = publicKey.getAlgorithm();
        BcContentSignerBuilder signerBuilder;
        if (algorithm.equals("SM2")) {
            AlgorithmIdentifier signAlg = new AlgorithmIdentifier(SignAlgEnum.SM3_WITH_SM2.getOid());
            AlgorithmIdentifier digAlg = new AlgorithmIdentifier(DigestAlgEnum.SM3.getOid());
            signerBuilder = new BcECContentSignerBuilder(signAlg, digAlg);
        } else {
            AlgorithmIdentifier signAlg = new AlgorithmIdentifier(SignAlgEnum.SHA256_WITH_RSA.getOid());
            AlgorithmIdentifier digAlg = new AlgorithmIdentifier(DigestAlgEnum.SHA256.getOid());
            signerBuilder = new BcRSAContentSignerBuilder(signAlg, digAlg);
        }
        AsymmetricKeyParameter parameter = new AsymmetricKeyParameter(true);
        builder.build(signerBuilder.build(parameter));

    }

    /**
     * @param [list]
     * @return com.github.zhenwei.core.asn1.ASN1EncodableVector
     * @author zhangzhenwei
     * @description parseExtension 解析扩展项
     * @since: 1.0.0
     * @date 2022/2/21 10:33 下午
     */
    private ASN1EncodableVector parseExtension(List<CertExtension> list) throws WeGooCryptoException {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (CertExtension certExtension : list) {
            DERSet valueSet = new DERSet(CodingType.encode(certExtension.getCodingType(), certExtension.getValue()));
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(certExtension.getKey());
            Attribute attribute = new Attribute(oid, valueSet);
            vector.add(attribute);
        }
        return vector;
    }


}