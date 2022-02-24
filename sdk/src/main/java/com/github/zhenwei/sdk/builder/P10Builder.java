package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.DERSet;
import com.github.zhenwei.core.asn1.pkcs.CertificationRequestInfo;
import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.ECDomainParameters;
import com.github.zhenwei.core.crypto.params.ECPrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.RSAKeyParameters;
import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.pkix.operator.bc.BcContentSignerBuilder;
import com.github.zhenwei.pkix.operator.bc.BcECContentSignerBuilder;
import com.github.zhenwei.pkix.operator.bc.BcRSAContentSignerBuilder;
import com.github.zhenwei.pkix.pkcs.PKCS10CertificationRequest;
import com.github.zhenwei.pkix.pkcs.PKCS10CertificationRequestBuilder;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import com.github.zhenwei.provider.jce.interfaces.ECPrivateKey;
import com.github.zhenwei.provider.jce.spec.ECParameterSpec;
import com.github.zhenwei.sdk.builder.params.CertExtension;
import com.github.zhenwei.sdk.builder.params.CodingType;
import com.github.zhenwei.sdk.enums.DigestAlgEnum;
import com.github.zhenwei.sdk.enums.KeyPairAlgEnum;
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
    public P10Builder(String dn, PublicKey publicKey, PrivateKey privateKey, List<CertExtension> list) throws WeGooCryptoException, OperatorCreationException, IOException {

        X500Name name = new X500Name(dn);

        ASN1Set set = new DERSet();
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        // 主题, 公钥, 扩展项
        CertificationRequestInfo requestInfo = new CertificationRequestInfo(name, keyInfo, set);

        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(name, keyInfo);
        parseExtension(list, builder);
        String algorithm = publicKey.getAlgorithm();
        BcContentSignerBuilder signerBuilder;
        AsymmetricKeyParameter parameter;
        //todo 算法标识
        if (algorithm.equals(KeyPairAlgEnum.SM2_256.getAlg())) {
            AlgorithmIdentifier signAlg = new AlgorithmIdentifier(SignAlgEnum.SM3_WITH_SM2.getOid());
            AlgorithmIdentifier digAlg = new AlgorithmIdentifier(DigestAlgEnum.SM3.getOid());
            signerBuilder = new BcECContentSignerBuilder(signAlg, digAlg);
            ECPrivateKey key = (ECPrivateKey) privateKey;
            ECParameterSpec parameters = key.getParameters();
            ECDomainParameters ecDomainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(),
                    parameters.getN(), parameters.getH(), parameters.getSeed());
            parameter = new ECPrivateKeyParameters(key.getD(), ecDomainParameters);
        } else {
            AlgorithmIdentifier signAlg = new AlgorithmIdentifier(SignAlgEnum.SHA256_WITH_RSA.getOid());
            AlgorithmIdentifier digAlg = new AlgorithmIdentifier(DigestAlgEnum.SHA256.getOid());
            signerBuilder = new BcRSAContentSignerBuilder(signAlg, digAlg);
            BCRSAPrivateKey key = (BCRSAPrivateKey) privateKey;
            parameter = new RSAKeyParameters(true, key.getModulus(), key.getPrivateExponent());

        }

        request = builder.build(signerBuilder.build(parameter));
        System.out.println(Hex.toHexString(request.getEncoded()));

    }

    /**
     * @param [list]
     * @return com.github.zhenwei.core.asn1.ASN1EncodableVector
     * @author zhangzhenwei
     * @description parseExtension 解析扩展项
     * @since: 1.0.0
     * @date 2022/2/21 10:33 下午
     */
    private void parseExtension(List<CertExtension> list, PKCS10CertificationRequestBuilder builder) throws WeGooCryptoException {
//        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (list != null) {
            for (CertExtension certExtension : list) {
//                DERSet valueSet = new DERSet(CodingType.encode(certExtension.getCodingType(), certExtension.getValue()));
                ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(certExtension.getKey());
//                Attribute attribute = new Attribute(oid, valueSet);
//                vector.add(attribute);
                builder.addAttribute(oid, CodingType.encode(certExtension.getCodingType(), certExtension.getValue()));
            }
        }
//        return vector;
    }




}