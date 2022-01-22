package com.github.zhenwei.pkix.its.operator;








import java.io.IOException;
import org.bouncycastle.oer.its.EccP256CurvePoint;
import org.bouncycastle.oer.its.EccP384CurvePoint;
import org.bouncycastle.oer.its.EcdsaP256Signature;
import org.bouncycastle.oer.its.EcdsaP384Signature;
import org.bouncycastle.oer.its.Signature;
 
import sec.SECObjectIdentifiers;
import teletrust.TeleTrusTObjectIdentifiers;

public class ECDSAEncoder
{
    public static byte[] toX962(Signature signature)
    {
        byte[] r;
        byte[] s;
        if (signature.getChoice() == Signature.ecdsaNistP256Signature || signature.getChoice() == Signature.ecdsaBrainpoolP256r1Signature)
        {
            EcdsaP256Signature sig = EcdsaP256Signature.getInstance(signature.getValue());
            r = ASN1OctetString.getInstance(sig.getrSig().getValue()).getOctets();
            s = sig.getsSig().getOctets();
        }
        else
        {
            EcdsaP384Signature sig = EcdsaP384Signature.getInstance(signature.getValue());
            r = ASN1OctetString.getInstance(sig.getrSig().getValue()).getOctets();
            s = sig.getsSig().getOctets();
        }

        try
        {
            return new DERSequence(new ASN1Encodable[]{new ASN1Integer(BigIntegers.fromUnsignedByteArray(r)),
                new ASN1Integer(BigIntegers.fromUnsignedByteArray(s))}).getEncoded();
        }
        catch (IOException ioException)
        {
            throw new RuntimeException("der encoding r & s");
        }
    }

    public static Signature toITS(ASN1ObjectIdentifier curveID, byte[] dsaEncoding)
    {
        ASN1Sequence asn1Sig = ASN1Sequence.getInstance(dsaEncoding);

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return new Signature(Signature.ecdsaNistP256Signature, new EcdsaP256Signature(
                new EccP256CurvePoint(EccP256CurvePoint.xOnly, new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(0)).getValue()))),
                new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(1)).getValue()))));
        }
        if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return new Signature(Signature.ecdsaBrainpoolP256r1Signature, new EcdsaP256Signature(
                new EccP256CurvePoint(EccP256CurvePoint.xOnly, new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(0)).getValue()))),
                new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(1)).getValue()))));
        }
        if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            return new Signature(Signature.ecdsaBrainpoolP384r1Signature, new EcdsaP384Signature(
                new EccP384CurvePoint(EccP384CurvePoint.xOnly, new DEROctetString(BigIntegers.asUnsignedByteArray(48, ASN1Integer.getInstance(asn1Sig.getObjectAt(0)).getValue()))),
                new DEROctetString(BigIntegers.asUnsignedByteArray(48, ASN1Integer.getInstance(asn1Sig.getObjectAt(1)).getValue()))));
        }

        throw new IllegalArgumentException("unknown curveID");
    }
}