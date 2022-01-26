package com.github.zhenwei.provider.jcajce.provider.asymmetric.ec;

import com.github.zhenwei.core.asn1.ASN1BitString;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.asn1.x9.X962Parameters;
import com.github.zhenwei.core.asn1.x9.X9ECPoint;
import com.github.zhenwei.core.asn1.x9.X9IntegerConverter;
import com.github.zhenwei.core.asn1.x9.X9ObjectIdentifiers;
import com.github.zhenwei.core.crypto.params.ECDomainParameters;
import com.github.zhenwei.core.crypto.params.ECPublicKeyParameters;
import com.github.zhenwei.core.math.ec.ECCurve;
import com.github.zhenwei.core.util.Properties;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.util.EC5Util;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.util.ECUtil;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.util.KeyUtil;
import com.github.zhenwei.provider.jcajce.provider.config.ProviderConfiguration;
import com.github.zhenwei.provider.jce.interfaces.ECPointEncoder;
import com.github.zhenwei.provider.jce.provider.ChaosProvider;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

public class BCECPublicKey
    implements ECPublicKey, com.github.zhenwei.provider.jce.interfaces.ECPublicKey, ECPointEncoder {

  static final long serialVersionUID = 2422789860422731812L;

  private String algorithm = "EC";
  private boolean withCompression;

  private transient ECPublicKeyParameters ecPublicKey;
  private transient ECParameterSpec ecSpec;
  private transient ProviderConfiguration configuration;

  public BCECPublicKey(
      String algorithm,
      BCECPublicKey key) {
    this.algorithm = algorithm;
    this.ecPublicKey = key.ecPublicKey;
    this.ecSpec = key.ecSpec;
    this.withCompression = key.withCompression;
    this.configuration = key.configuration;
  }

  public BCECPublicKey(
      String algorithm,
      ECPublicKeySpec spec,
      ProviderConfiguration configuration) {
    this.algorithm = algorithm;
    this.ecSpec = spec.getParams();
    this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(ecSpec, spec.getW()),
        EC5Util.getDomainParameters(configuration, spec.getParams()));
    this.configuration = configuration;
  }

  public BCECPublicKey(
      String algorithm,
      com.github.zhenwei.provider.jce.spec.ECPublicKeySpec spec,
      ProviderConfiguration configuration) {
    this.algorithm = algorithm;

    if (spec.getParams() != null) // can be null if implictlyCa
    {
      ECCurve curve = spec.getParams().getCurve();
      EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());

      // this may seem a little long-winded but it's how we pick up the custom curve.
      this.ecPublicKey = new ECPublicKeyParameters(
          spec.getQ(), ECUtil.getDomainParameters(configuration, spec.getParams()));
      this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec.getParams());
    } else {
      com.github.zhenwei.provider.jce.spec.ECParameterSpec s = configuration.getEcImplicitlyCa();

      this.ecPublicKey = new ECPublicKeyParameters(s.getCurve()
          .createPoint(spec.getQ().getAffineXCoord().toBigInteger(),
              spec.getQ().getAffineYCoord().toBigInteger()),
          EC5Util.getDomainParameters(configuration, (ECParameterSpec) null));
      this.ecSpec = null;
    }

    this.configuration = configuration;
  }

  public BCECPublicKey(
      String algorithm,
      ECPublicKeyParameters params,
      ECParameterSpec spec,
      ProviderConfiguration configuration) {
    ECDomainParameters dp = params.getParameters();

    this.algorithm = algorithm;
    this.ecPublicKey = params;

    if (spec == null) {
      EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

      this.ecSpec = createSpec(ellipticCurve, dp);
    } else {
      this.ecSpec = spec;
    }

    this.configuration = configuration;
  }

  public BCECPublicKey(
      String algorithm,
      ECPublicKeyParameters params,
      com.github.zhenwei.provider.jce.spec.ECParameterSpec spec,
      ProviderConfiguration configuration) {
    ECDomainParameters dp = params.getParameters();

    this.algorithm = algorithm;

    if (spec == null) {
      EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

      this.ecSpec = createSpec(ellipticCurve, dp);
    } else {
      EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

      this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec);
    }

    this.ecPublicKey = params;
    this.configuration = configuration;
  }

  /*
   * called for implicitCA
   */
  public BCECPublicKey(
      String algorithm,
      ECPublicKeyParameters params,
      ProviderConfiguration configuration) {
    this.algorithm = algorithm;
    this.ecPublicKey = params;
    this.ecSpec = null;
    this.configuration = configuration;
  }

  public BCECPublicKey(
      ECPublicKey key,
      ProviderConfiguration configuration) {
    this.algorithm = key.getAlgorithm();
    this.ecSpec = key.getParams();
    this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(this.ecSpec, key.getW()),
        EC5Util.getDomainParameters(configuration, key.getParams()));
    this.configuration = configuration;
  }

  BCECPublicKey(
      String algorithm,
      SubjectPublicKeyInfo info,
      ProviderConfiguration configuration) {
    this.algorithm = algorithm;
    this.configuration = configuration;
    populateFromPubKeyInfo(info);
  }

  private ECParameterSpec createSpec(EllipticCurve ellipticCurve, ECDomainParameters dp) {
    return new ECParameterSpec(
        ellipticCurve,
        EC5Util.convertPoint(dp.getG()),
        dp.getN(),
        dp.getH().intValue());
  }

  private void populateFromPubKeyInfo(SubjectPublicKeyInfo info) {
    X962Parameters params = X962Parameters.getInstance(info.getAlgorithm().getParameters());
    ECCurve curve = EC5Util.getCurve(configuration, params);
    ecSpec = EC5Util.convertToSpec(params, curve);

    ASN1BitString bits = info.getPublicKeyData();
    byte[] data = bits.getBytes();
    ASN1OctetString key = new DEROctetString(data);

    //
    // extra octet string - one of our old certs...
    //
    if (data[0] == 0x04 && data[1] == data.length - 2
        && (data[2] == 0x02 || data[2] == 0x03)) {
      int qLength = new X9IntegerConverter().getByteLength(curve);

      if (qLength >= data.length - 3) {
        try {
          key = (ASN1OctetString) ASN1Primitive.fromByteArray(data);
        } catch (IOException ex) {
          throw new IllegalArgumentException("error recovering public key");
        }
      }
    }

    X9ECPoint derQ = new X9ECPoint(curve, key);

    this.ecPublicKey = new ECPublicKeyParameters(derQ.getPoint(),
        ECUtil.getDomainParameters(configuration, params));
  }

  public String getAlgorithm() {
    return algorithm;
  }

  public String getFormat() {
    return "X.509";
  }

  public byte[] getEncoded() {
    boolean compress = withCompression || Properties.isOverrideSet("org.bouncycastle.ec.enable_pc");

    AlgorithmIdentifier algId = new AlgorithmIdentifier(
        X9ObjectIdentifiers.id_ecPublicKey,
        ECUtils.getDomainParametersFromName(ecSpec, compress));

    byte[] pubKeyOctets = ecPublicKey.getQ().getEncoded(compress);

    // stored curve is null if ImplicitlyCa
    return KeyUtil.getEncodedSubjectPublicKeyInfo(algId, pubKeyOctets);
  }

  public ECParameterSpec getParams() {
    return ecSpec;
  }

  public com.github.zhenwei.provider.jce.spec.ECParameterSpec getParameters() {
    if (ecSpec == null)     // implictlyCA
    {
      return null;
    }

    return EC5Util.convertSpec(ecSpec);
  }

  public ECPoint getW() {
    return EC5Util.convertPoint(ecPublicKey.getQ());
  }

  public com.github.zhenwei.core.math.ec.ECPoint getQ() {
    com.github.zhenwei.core.math.ec.ECPoint q = ecPublicKey.getQ();

    if (ecSpec == null) {
      return q.getDetachedPoint();
    }

    return q;
  }

  ECPublicKeyParameters engineGetKeyParameters() {
    return ecPublicKey;
  }

  com.github.zhenwei.provider.jce.spec.ECParameterSpec engineGetSpec() {
    if (ecSpec != null) {
      return EC5Util.convertSpec(ecSpec);
    }

    return configuration.getEcImplicitlyCa();
  }

  public String toString() {
    return ECUtil.publicKeyToString("EC", ecPublicKey.getQ(), engineGetSpec());
  }

  public void setPointFormat(String style) {
    withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
  }

  public boolean equals(Object o) {
    if (!(o instanceof BCECPublicKey)) {
      return false;
    }

    BCECPublicKey other = (BCECPublicKey) o;

    return ecPublicKey.getQ().equals(other.ecPublicKey.getQ()) && (engineGetSpec().equals(
        other.engineGetSpec()));
  }

  public int hashCode() {
    return ecPublicKey.getQ().hashCode() ^ engineGetSpec().hashCode();
  }

  private void readObject(
      ObjectInputStream in)
      throws IOException, ClassNotFoundException {
    in.defaultReadObject();

    byte[] enc = (byte[]) in.readObject();

    this.configuration = ChaosProvider.CONFIGURATION;

    populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));
  }

  private void writeObject(
      ObjectOutputStream out)
      throws IOException {
    out.defaultWriteObject();

    out.writeObject(this.getEncoded());
  }
}