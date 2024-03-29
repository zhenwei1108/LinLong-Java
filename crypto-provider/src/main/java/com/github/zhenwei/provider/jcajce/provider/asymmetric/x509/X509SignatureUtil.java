package com.github.zhenwei.provider.jcajce.provider.asymmetric.x509;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Null;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.edec.EdECObjectIdentifiers;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.core.asn1.misc.MiscObjectIdentifiers;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.RSASSAPSSparams;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x9.X9ObjectIdentifiers;
import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.provider.jcajce.util.MessageDigestUtils;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PSSParameterSpec;
import java.util.HashMap;
import java.util.Map;

class X509SignatureUtil {

  private static final Map<ASN1ObjectIdentifier, String> algNames = new HashMap<ASN1ObjectIdentifier, String>();

  static {
    algNames.put(EdECObjectIdentifiers.id_Ed25519, "Ed25519");
    algNames.put(EdECObjectIdentifiers.id_Ed448, "Ed448");
    algNames.put(OIWObjectIdentifiers.dsaWithSHA1, "SHA1withDSA");
    algNames.put(X9ObjectIdentifiers.id_dsa_with_sha1, "SHA1withDSA");
    algNames.put(GMObjectIdentifiers.sm2sign_with_sm3, "SM3WITHSM2");
  }

  private static final ASN1Null derNull = DERNull.INSTANCE;

  static boolean isCompositeAlgorithm(AlgorithmIdentifier algorithmIdentifier) {
    return MiscObjectIdentifiers.id_alg_composite.equals(algorithmIdentifier.getAlgorithm());
  }

  static void setSignatureParameters(
      Signature signature,
      ASN1Encodable params)
      throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    if (params != null && !derNull.equals(params)) {
      AlgorithmParameters sigParams = AlgorithmParameters.getInstance(signature.getAlgorithm(),
          signature.getProvider());

      try {
        sigParams.init(params.toASN1Primitive().getEncoded());
      } catch (IOException e) {
        throw new SignatureException("IOException decoding parameters: " + e.getMessage());
      }

      if (signature.getAlgorithm().endsWith("MGF1")) {
        try {
          signature.setParameter(sigParams.getParameterSpec(PSSParameterSpec.class));
        } catch (GeneralSecurityException e) {
          throw new SignatureException("Exception extracting parameters: " + e.getMessage());
        }
      }
    }
  }

  static String getSignatureName(
      AlgorithmIdentifier sigAlgId) {
    ASN1Encodable params = sigAlgId.getParameters();

    if (params != null && !derNull.equals(params)) {
      if (sigAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS)) {
        RSASSAPSSparams rsaParams = RSASSAPSSparams.getInstance(params);

        return getDigestAlgName(rsaParams.getHashAlgorithm().getAlgorithm()) + "withRSAandMGF1";
      }
      if (sigAlgId.getAlgorithm().equals(X9ObjectIdentifiers.ecdsa_with_SHA2)) {
        ASN1Sequence ecDsaParams = ASN1Sequence.getInstance(params);

        return getDigestAlgName((ASN1ObjectIdentifier) ecDsaParams.getObjectAt(0)) + "withECDSA";
      }
    }

    // deal with the "weird" ones.
    String algName = (String) algNames.get(sigAlgId.getAlgorithm());
    if (algName != null) {
      return algName;
    }

    return findAlgName(sigAlgId.getAlgorithm());
  }

  /**
   * Return the digest algorithm using one of the standard JCA string representations rather the the
   * algorithm identifier (if possible).
   */
  private static String getDigestAlgName(
      ASN1ObjectIdentifier digestAlgOID) {
    String name = MessageDigestUtils.getDigestName(digestAlgOID);

    int dIndex = name.indexOf('-');
    if (dIndex > 0 && !name.startsWith("SHA3")) {
      return name.substring(0, dIndex) + name.substring(dIndex + 1);
    }

    return name;
  }

  private static String findAlgName(ASN1ObjectIdentifier algOid) {
    Provider prov = Security.getProvider(WeGooProvider.PROVIDER_NAME);

    if (prov != null) {
      String algName = lookupAlg(prov, algOid);
      if (algName != null) {
        return algName;
      }
    }

    Provider[] provs = Security.getProviders();

    for (int i = 0; i != provs.length; i++) {
      if (prov != provs[i]) {
        String algName = lookupAlg(provs[i], algOid);
        if (algName != null) {
          return algName;
        }
      }
    }

    return algOid.getId();
  }

  private static String lookupAlg(Provider prov, ASN1ObjectIdentifier algOid) {
    String algName = prov.getProperty("Alg.Alias.Signature." + algOid);

    if (algName != null) {
      return algName;
    }

    algName = prov.getProperty("Alg.Alias.Signature.OID." + algOid);

    if (algName != null) {
      return algName;
    }

    return null;
  }

  static void prettyPrintSignature(byte[] sig, StringBuffer buf, String nl) {
    if (sig.length > 20) {
      buf.append("            Signature: ").append(Hex.toHexString(sig, 0, 20)).append(nl);
      for (int i = 20; i < sig.length; i += 20) {
        if (i < sig.length - 20) {
          buf.append("                       ").append(Hex.toHexString(sig, i, 20)).append(nl);
        } else {
          buf.append("                       ").append(Hex.toHexString(sig, i, sig.length - i))
              .append(nl);
        }
      }
    } else {
      buf.append("            Signature: ").append(Hex.toHexString(sig)).append(nl);
    }
  }

}