package com.github.zhenwei.core.pqc.crypto.util;

import java.io.IOException;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.isara.IsaraObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.pqc.asn1.McElieceCCA2PublicKey;
import com.github.zhenwei.core.pqc.asn1.PQCObjectIdentifiers;
import com.github.zhenwei.core.pqc.asn1.SPHINCS256KeyParams;
import com.github.zhenwei.core.pqc.asn1.XMSSKeyParams;
import com.github.zhenwei.core.pqc.asn1.XMSSMTKeyParams;
import com.github.zhenwei.core.pqc.asn1.XMSSMTPublicKey;
import com.github.zhenwei.core.pqc.asn1.XMSSPublicKey;
import com.github.zhenwei.core.pqc.crypto.lms.Composer;
import com.github.zhenwei.core.pqc.crypto.lms.HSSPublicKeyParameters;
import com.github.zhenwei.core.pqc.crypto.lms.LMSPublicKeyParameters;
import com.github.zhenwei.core.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import com.github.zhenwei.core.pqc.crypto.newhope.NHPublicKeyParameters;
import com.github.zhenwei.core.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import com.github.zhenwei.core.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import com.github.zhenwei.core.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import com.github.zhenwei.core.pqc.crypto.xmss.XMSSPublicKeyParameters;

/**
 * Factory to create ASN.1 subject public key info objects from lightweight public keys.
 */
public class SubjectPublicKeyInfoFactory
{
    private SubjectPublicKeyInfoFactory()
    {

    }

    /**
     * Create a SubjectPublicKeyInfo public key.
     *
     * @param publicKey the key to be encoded into the info object.
     * @return a SubjectPublicKeyInfo representing the key.
     * @throws IOException on an error encoding the key
     */
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        throws IOException
    {
        if (publicKey instanceof QTESLAPublicKeyParameters)
        {
            QTESLAPublicKeyParameters keyParams = (QTESLAPublicKeyParameters)publicKey;
            AlgorithmIdentifier algorithmIdentifier = Utils.qTeslaLookupAlgID(keyParams.getSecurityCategory());

            return new SubjectPublicKeyInfo(algorithmIdentifier, keyParams.getPublicData());
        }
        else if (publicKey instanceof SPHINCSPublicKeyParameters)
        {
            SPHINCSPublicKeyParameters params = (SPHINCSPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256,
                new SPHINCS256KeyParams(Utils.sphincs256LookupTreeAlgID(params.getTreeDigest())));
            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getKeyData());
        }
        else if (publicKey instanceof NHPublicKeyParameters)
        {
            NHPublicKeyParameters params = (NHPublicKeyParameters)publicKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);
            return new SubjectPublicKeyInfo(algorithmIdentifier, params.getPubData());
        }
        else if (publicKey instanceof LMSPublicKeyParameters)
        {
            LMSPublicKeyParameters params = (LMSPublicKeyParameters)publicKey;

            byte[] encoding = Composer.compose().u32str(1).bytes(params).build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
        }
        else if (publicKey instanceof HSSPublicKeyParameters)
        {
            HSSPublicKeyParameters params = (HSSPublicKeyParameters)publicKey;

            byte[] encoding = Composer.compose().u32str(params.getL()).bytes(params.getLMSPublicKey()).build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
        }
        else if (publicKey instanceof XMSSPublicKeyParameters)
        {
            XMSSPublicKeyParameters keyParams = (XMSSPublicKeyParameters)publicKey;

            byte[] publicSeed = keyParams.getPublicSeed();
            byte[] root = keyParams.getRoot();
            byte[] keyEnc = keyParams.getEncoded();
            if (keyEnc.length > publicSeed.length + root.length)
            {
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(IsaraObjectIdentifiers.id_alg_xmss);

                return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(keyEnc));
            }
            else
            {
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss,
                    new XMSSKeyParams(keyParams.getParameters().getHeight(), Utils.xmssLookupTreeAlgID(keyParams.getTreeDigest())));

                return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSPublicKey(publicSeed, root));
            }
        }
        else if (publicKey instanceof XMSSMTPublicKeyParameters)
        {
            XMSSMTPublicKeyParameters keyParams = (XMSSMTPublicKeyParameters)publicKey;

            byte[] publicSeed = keyParams.getPublicSeed();
            byte[] root = keyParams.getRoot();
            byte[] keyEnc = keyParams.getEncoded();
            if (keyEnc.length > publicSeed.length + root.length)
            {
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(IsaraObjectIdentifiers.id_alg_xmssmt);

                return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(keyEnc));
            }
            else
            {
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt, new XMSSMTKeyParams(keyParams.getParameters().getHeight(), keyParams.getParameters().getLayers(),
                    Utils.xmssLookupTreeAlgID(keyParams.getTreeDigest())));
                return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSMTPublicKey(keyParams.getPublicSeed(), keyParams.getRoot()));
            }
        }
        else if (publicKey instanceof McElieceCCA2PublicKeyParameters)
        {
            McElieceCCA2PublicKeyParameters pub = (McElieceCCA2PublicKeyParameters)publicKey;
            McElieceCCA2PublicKey mcEliecePub = new McElieceCCA2PublicKey(pub.getN(), pub.getT(), pub.getG(), Utils.getAlgorithmIdentifier(pub.getDigest()));
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.mcElieceCca2);

            return new SubjectPublicKeyInfo(algorithmIdentifier, mcEliecePub);
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }
}