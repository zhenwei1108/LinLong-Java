package com.github.zhenwei.core.crypto.util;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1InputStream;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.github.zhenwei.core.asn1.cryptopro.ECGOST3410NamedCurves;
import com.github.zhenwei.core.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import com.github.zhenwei.core.asn1.edec.EdECObjectIdentifiers;
import com.github.zhenwei.core.asn1.oiw.ElGamalParameter;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.DHParameter;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.asn1.pkcs.RSAPrivateKey;
import com.github.zhenwei.core.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.github.zhenwei.core.asn1.sec.ECPrivateKey;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.DSAParameter;
import com.github.zhenwei.core.asn1.x509.X509ObjectIdentifiers;
import com.github.zhenwei.core.asn1.x9.ECNamedCurveTable;
import com.github.zhenwei.core.asn1.x9.X962Parameters;
import com.github.zhenwei.core.asn1.x9.X9ECParameters;
import com.github.zhenwei.core.asn1.x9.X9ObjectIdentifiers;
import com.github.zhenwei.core.crypto.ec.CustomNamedCurves;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.DHParameters;
import com.github.zhenwei.core.crypto.params.DHPrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.DSAParameters;
import com.github.zhenwei.core.crypto.params.DSAPrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.ECDomainParameters;
import com.github.zhenwei.core.crypto.params.ECGOST3410Parameters;
import com.github.zhenwei.core.crypto.params.ECNamedDomainParameters;
import com.github.zhenwei.core.crypto.params.ECPrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.Ed25519PrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.Ed448PrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.ElGamalParameters;
import com.github.zhenwei.core.crypto.params.ElGamalPrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.RSAPrivateCrtKeyParameters;
import com.github.zhenwei.core.crypto.params.X25519PrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.X448PrivateKeyParameters;
import com.github.zhenwei.core.util.Arrays;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

/**
 * Factory for creating private key objects from PKCS8 PrivateKeyInfo objects.
 */
public class PrivateKeyFactory {

  /**
   * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding.
   *
   * @param privateKeyInfoData the PrivateKeyInfo encoding
   * @return a suitable private key parameter
   * @throws IOException on an error decoding the key
   */
  public static AsymmetricKeyParameter createKey(byte[] privateKeyInfoData)
      throws IOException {
    return createKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privateKeyInfoData)));
  }

  /**
   * Create a private key parameter from a PKCS8 PrivateKeyInfo encoding read from a stream.
   *
   * @param inStr the stream to read the PrivateKeyInfo encoding from
   * @return a suitable private key parameter
   * @throws IOException on an error decoding the key
   */
  public static AsymmetricKeyParameter createKey(InputStream inStr)
      throws IOException {
    return createKey(PrivateKeyInfo.getInstance(new ASN1InputStream(inStr).readObject()));
  }

  /**
   * Create a private key parameter from the passed in PKCS8 PrivateKeyInfo object.
   *
   * @param keyInfo the PrivateKeyInfo object containing the key material
   * @return a suitable private key parameter
   * @throws IOException on an error decoding the key
   */
  public static AsymmetricKeyParameter createKey(PrivateKeyInfo keyInfo)
      throws IOException {
    AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
    ASN1ObjectIdentifier algOID = algId.getAlgorithm();

    if (algOID.equals(PKCSObjectIdentifiers.rsaEncryption)
        || algOID.equals(PKCSObjectIdentifiers.id_RSASSA_PSS)
        || algOID.equals(X509ObjectIdentifiers.id_ea_rsa)) {
      RSAPrivateKey keyStructure = RSAPrivateKey.getInstance(keyInfo.parsePrivateKey());

      return new RSAPrivateCrtKeyParameters(keyStructure.getModulus(),
          keyStructure.getPublicExponent(), keyStructure.getPrivateExponent(),
          keyStructure.getPrime1(), keyStructure.getPrime2(), keyStructure.getExponent1(),
          keyStructure.getExponent2(), keyStructure.getCoefficient());
    }
    // TODO?
//      else if (algOID.equals(X9ObjectIdentifiers.dhpublicnumber))
    else if (algOID.equals(PKCSObjectIdentifiers.dhKeyAgreement)) {
      DHParameter params = DHParameter.getInstance(algId.getParameters());
      ASN1Integer derX = (ASN1Integer) keyInfo.parsePrivateKey();

      BigInteger lVal = params.getL();
      int l = lVal == null ? 0 : lVal.intValue();
      DHParameters dhParams = new DHParameters(params.getP(), params.getG(), null, l);

      return new DHPrivateKeyParameters(derX.getValue(), dhParams);
    } else if (algOID.equals(OIWObjectIdentifiers.elGamalAlgorithm)) {
      ElGamalParameter params = ElGamalParameter.getInstance(algId.getParameters());
      ASN1Integer derX = (ASN1Integer) keyInfo.parsePrivateKey();

      return new ElGamalPrivateKeyParameters(derX.getValue(), new ElGamalParameters(
          params.getP(), params.getG()));
    } else if (algOID.equals(X9ObjectIdentifiers.id_dsa)) {
      ASN1Integer derX = (ASN1Integer) keyInfo.parsePrivateKey();
      ASN1Encodable algParameters = algId.getParameters();

      DSAParameters parameters = null;
      if (algParameters != null) {
        DSAParameter params = DSAParameter.getInstance(algParameters.toASN1Primitive());
        parameters = new DSAParameters(params.getP(), params.getQ(), params.getG());
      }

      return new DSAPrivateKeyParameters(derX.getValue(), parameters);
    } else if (algOID.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
      X962Parameters params = X962Parameters.getInstance(algId.getParameters());

      X9ECParameters x9;
      ECDomainParameters dParams;

      if (params.isNamedCurve()) {
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) params.getParameters();

        x9 = CustomNamedCurves.getByOID(oid);
        if (x9 == null) {
          x9 = ECNamedCurveTable.getByOID(oid);
        }
        dParams = new ECNamedDomainParameters(oid, x9);
      } else {
        x9 = X9ECParameters.getInstance(params.getParameters());
        dParams = new ECDomainParameters(
            x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
      }

      ECPrivateKey ec = ECPrivateKey.getInstance(keyInfo.parsePrivateKey());
      BigInteger d = ec.getKey();

      return new ECPrivateKeyParameters(d, dParams);
    } else if (algOID.equals(EdECObjectIdentifiers.id_X25519)) {
      return new X25519PrivateKeyParameters(getRawKey(keyInfo));
    } else if (algOID.equals(EdECObjectIdentifiers.id_X448)) {
      return new X448PrivateKeyParameters(getRawKey(keyInfo));
    } else if (algOID.equals(EdECObjectIdentifiers.id_Ed25519)) {
      return new Ed25519PrivateKeyParameters(getRawKey(keyInfo));
    } else if (algOID.equals(EdECObjectIdentifiers.id_Ed448)) {
      return new Ed448PrivateKeyParameters(getRawKey(keyInfo));
    } else if (
        algOID.equals(CryptoProObjectIdentifiers.gostR3410_2001) ||
            algOID.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512) ||
            algOID.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256)) {
      ASN1Encodable algParameters = algId.getParameters();
      GOST3410PublicKeyAlgParameters gostParams = GOST3410PublicKeyAlgParameters.getInstance(
          algParameters);
      ECGOST3410Parameters ecSpec = null;
      BigInteger d = null;
      ASN1Primitive p = algParameters.toASN1Primitive();
      if (p instanceof ASN1Sequence && (ASN1Sequence.getInstance(p).size() == 2
          || ASN1Sequence.getInstance(p).size() == 3)) {
        X9ECParameters ecP = ECGOST3410NamedCurves.getByOIDX9(gostParams.getPublicKeyParamSet());

        ecSpec = new ECGOST3410Parameters(
            new ECNamedDomainParameters(
                gostParams.getPublicKeyParamSet(), ecP),
            gostParams.getPublicKeyParamSet(),
            gostParams.getDigestParamSet(),
            gostParams.getEncryptionParamSet());
        ASN1OctetString privEnc = keyInfo.getPrivateKey();

        if (privEnc.getOctets().length == 32 || privEnc.getOctets().length == 64) {
          d = new BigInteger(1, Arrays.reverse(privEnc.getOctets()));
        } else {
          ASN1Encodable privKey = keyInfo.parsePrivateKey();
          if (privKey instanceof ASN1Integer) {
            d = ASN1Integer.getInstance(privKey).getPositiveValue();
          } else {
            byte[] dVal = Arrays.reverse(ASN1OctetString.getInstance(privKey).getOctets());
            d = new BigInteger(1, dVal);
          }
        }
      } else {
        X962Parameters params = X962Parameters.getInstance(algId.getParameters());

        if (params.isNamedCurve()) {
          ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
          X9ECParameters ecP = ECNamedCurveTable.getByOID(oid);

          ecSpec = new ECGOST3410Parameters(new ECNamedDomainParameters(oid, ecP),
              gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet(),
              gostParams.getEncryptionParamSet());
        } else if (params.isImplicitlyCA()) {
          ecSpec = null;
        } else {
          X9ECParameters ecP = X9ECParameters.getInstance(params.getParameters());
          ecSpec = new ECGOST3410Parameters(new ECNamedDomainParameters(algOID, ecP),
              gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet(),
              gostParams.getEncryptionParamSet());
        }

        ASN1Encodable privKey = keyInfo.parsePrivateKey();
        if (privKey instanceof ASN1Integer) {
          ASN1Integer derD = ASN1Integer.getInstance(privKey);

          d = derD.getValue();
        } else {
          ECPrivateKey ec = ECPrivateKey.getInstance(privKey);

          d = ec.getKey();
        }

      }

      return new ECPrivateKeyParameters(
          d,
          new ECGOST3410Parameters(
              ecSpec,
              gostParams.getPublicKeyParamSet(),
              gostParams.getDigestParamSet(),
              gostParams.getEncryptionParamSet()));

    } else {
      throw new RuntimeException("algorithm identifier in private key not recognised");
    }
  }

  private static byte[] getRawKey(PrivateKeyInfo keyInfo) throws IOException {
    return ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
  }
}