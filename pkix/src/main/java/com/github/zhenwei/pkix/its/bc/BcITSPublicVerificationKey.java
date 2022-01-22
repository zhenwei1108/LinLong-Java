package com.github.zhenwei.pkix.its.bc;


import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.sec.SECObjectIdentifiers;
import com.github.zhenwei.core.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.github.zhenwei.core.asn1.x9.X9ECParameters;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.ECNamedDomainParameters;
import com.github.zhenwei.core.math.ec.ECCurve;
import nist.NISTNamedCurves;
 
import org.bouncycastle.its.ITSPublicVerificationKey;
import org.bouncycastle.oer.its.EccCurvePoint;
import org.bouncycastle.oer.its.EccP256CurvePoint;
import org.bouncycastle.oer.its.EccP384CurvePoint;
import org.bouncycastle.oer.its.PublicVerificationKey;
import teletrust.TeleTrusTNamedCurves;



public class BcITSPublicVerificationKey
    extends ITSPublicVerificationKey
{
    public BcITSPublicVerificationKey(PublicVerificationKey verificationKey)
    {
        super(verificationKey);
    }

    static PublicVerificationKey fromKeyParameters(ECPublicKeyParameters pubKey)
    {
        ASN1ObjectIdentifier curveID = ((ECNamedDomainParameters)pubKey.getParameters()).getName();
        ECPoint q  = pubKey.getQ();

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaNistP256,
                    EccP256CurvePoint.builder()
                        .createUncompressedP256(
                            q.getAffineXCoord().toBigInteger(),
                            q.getAffineYCoord().toBigInteger()));
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaBrainpoolP256r1,
                    EccP256CurvePoint.builder()
                        .createUncompressedP256(
                            q.getAffineXCoord().toBigInteger(),
                            q.getAffineYCoord().toBigInteger()));
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaBrainpoolP384r1,
                    EccP384CurvePoint.builder()
                        .createUncompressedP384(
                            q.getAffineXCoord().toBigInteger(),
                            q.getAffineYCoord().toBigInteger()));
        }
        else
        {
            throw new IllegalArgumentException("unknown curve in public encryption key");
        }
    }

    public BcITSPublicVerificationKey(AsymmetricKeyParameter verificationKey)
    {
        super(fromKeyParameters((ECPublicKeyParameters)verificationKey));
    }

    public AsymmetricKeyParameter getKey()
    {
        X9ECParameters params;
        ASN1ObjectIdentifier curveID;

        switch (verificationKey.getChoice())
        {
        case PublicVerificationKey.ecdsaNistP256:
            curveID = SECObjectIdentifiers.secp256r1;
            params = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
            break;
        case PublicVerificationKey.ecdsaBrainpoolP256r1:
            curveID = TeleTrusTObjectIdentifiers.brainpoolP256r1;
            params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1);
            break;
        case PublicVerificationKey.ecdsaBrainpoolP384r1:
            curveID = TeleTrusTObjectIdentifiers.brainpoolP384r1;
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
        return new ECPublicKeyParameters(point,
            new ECNamedDomainParameters(curveID, params));
    }
}