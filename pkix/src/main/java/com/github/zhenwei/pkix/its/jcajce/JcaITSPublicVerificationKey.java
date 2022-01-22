package com.github.zhenwei.pkix.its.jcajce;




 

import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import nist.NISTNamedCurves;
import org.bouncycastle.its.ITSPublicVerificationKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;


import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.oer.its.EccCurvePoint;
import org.bouncycastle.oer.its.EccP256CurvePoint;
import org.bouncycastle.oer.its.EccP384CurvePoint;
import org.bouncycastle.oer.its.PublicVerificationKey;
import sec.SECObjectIdentifiers;
import teletrust.TeleTrusTNamedCurves;
import teletrust.TeleTrusTObjectIdentifiers;
import x9.X9ECParameters;

public class JcaITSPublicVerificationKey
    extends ITSPublicVerificationKey
{
    public static class Builder
    {
        private JcaJceHelper helper = new DefaultJcaJceHelper();

        public Builder setProvider(Provider provider)
        {
            this.helper = new ProviderJcaJceHelper(provider);

            return this;
        }

        public Builder setProvider(String providerName)
        {
            this.helper = new NamedJcaJceHelper(providerName);

            return this;
        }

        public JcaITSPublicVerificationKey build(PublicVerificationKey verificationKey)
        {
            return new JcaITSPublicVerificationKey(verificationKey, helper);
        }

        public JcaITSPublicVerificationKey build(PublicKey verificationKey)
        {
            return new JcaITSPublicVerificationKey(verificationKey, helper);
        }
    }

    private final JcaJceHelper helper;

    JcaITSPublicVerificationKey(PublicVerificationKey encryptionKey, JcaJceHelper helper)
    {
        super(encryptionKey);
        this.helper = helper;
    }

    JcaITSPublicVerificationKey(PublicKey verificationKey, JcaJceHelper helper)
    {
        super(fromKeyParameters((ECPublicKey)verificationKey));
        this.helper = helper;
    }

    static PublicVerificationKey fromKeyParameters(ECPublicKey pubKey)
    {
        ASN1ObjectIdentifier curveID = ASN1ObjectIdentifier.getInstance(
            SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()).getAlgorithm().getParameters());

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaNistP256,
                EccP256CurvePoint.builder()
                    .createUncompressedP256(
                        pubKey.getW().getAffineX(),
                        pubKey.getW().getAffineY()));
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaBrainpoolP256r1,
                EccP256CurvePoint.builder()
                    .createUncompressedP256(
                        pubKey.getW().getAffineX(),
                        pubKey.getW().getAffineY()));
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaBrainpoolP384r1,
                EccP384CurvePoint.builder()
                    .createUncompressedP384(
                        pubKey.getW().getAffineX(),
                        pubKey.getW().getAffineY()));
        }
        else
        {
            throw new IllegalArgumentException("unknown curve in public encryption key");
        }
    }

    public PublicKey getKey()
    {
        X9ECParameters params;

        switch (verificationKey.getChoice())
        {
        case PublicVerificationKey.ecdsaNistP256:
            params = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
            break;
        case PublicVerificationKey.ecdsaBrainpoolP256r1:
            params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1);
            break;
        case PublicVerificationKey.ecdsaBrainpoolP384r1:
            params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP384r1);
            break;
        default:
            throw new IllegalStateException("unknown key type");
        }
        ECCurve curve = params.getCurve();

        ASN1Encodable pviCurvePoint = verificationKey.getCurvePoint();
        final EccCurvePoint itsPoint;
        if (pviCurvePoint instanceof EccCurvePoint)
        {
            itsPoint = (EccCurvePoint)verificationKey.getCurvePoint();
        }
        else
        {
            throw new IllegalStateException("extension to public verification key not supported");
        }

        byte[] key;

        if (itsPoint instanceof EccP256CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else if (itsPoint instanceof EccP384CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else
        {
            throw new IllegalStateException("unknown key type");
        }

        ECPoint point = curve.decodePoint(key).normalize();
        try
        {
            KeyFactory keyFactory = helper.createKeyFactory("EC");
            ECParameterSpec spec = EC5Util.convertToSpec(params);
            java.security.spec.ECPoint jPoint = EC5Util.convertPoint(point);
            return keyFactory.generatePublic(new ECPublicKeySpec(jPoint, spec));
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }
}