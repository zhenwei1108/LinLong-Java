package com.github.zhenwei.provider.jce.provider;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.oiw.ElGamalParameter;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.params.ElGamalPrivateKeyParameters;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.util.KeyUtil;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import com.github.zhenwei.provider.jce.interfaces.ElGamalPrivateKey;
import com.github.zhenwei.provider.jce.interfaces.PKCS12BagAttributeCarrier;
import com.github.zhenwei.provider.jce.spec.ElGamalParameterSpec;
import com.github.zhenwei.provider.jce.spec.ElGamalPrivateKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Enumeration;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;

public class JCEElGamalPrivateKey
    implements ElGamalPrivateKey, DHPrivateKey, PKCS12BagAttributeCarrier {

  static final long serialVersionUID = 4819350091141529678L;

  BigInteger x;

  ElGamalParameterSpec elSpec;

  private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

  protected JCEElGamalPrivateKey() {
  }

  JCEElGamalPrivateKey(
      ElGamalPrivateKey key) {
    this.x = key.getX();
    this.elSpec = key.getParameters();
  }

  JCEElGamalPrivateKey(
      DHPrivateKey key) {
    this.x = key.getX();
    this.elSpec = new ElGamalParameterSpec(key.getParams().getP(), key.getParams().getG());
  }

  JCEElGamalPrivateKey(
      ElGamalPrivateKeySpec spec) {
    this.x = spec.getX();
    this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
  }

  JCEElGamalPrivateKey(
      DHPrivateKeySpec spec) {
    this.x = spec.getX();
    this.elSpec = new ElGamalParameterSpec(spec.getP(), spec.getG());
  }

  JCEElGamalPrivateKey(
      PrivateKeyInfo info)
      throws IOException {
    ElGamalParameter params = ElGamalParameter.getInstance(
        info.getPrivateKeyAlgorithm().getParameters());
    ASN1Integer derX = ASN1Integer.getInstance(info.parsePrivateKey());

    this.x = derX.getValue();
    this.elSpec = new ElGamalParameterSpec(params.getP(), params.getG());
  }

  JCEElGamalPrivateKey(
      ElGamalPrivateKeyParameters params) {
    this.x = params.getX();
    this.elSpec = new ElGamalParameterSpec(params.getParameters().getP(),
        params.getParameters().getG());
  }

  public String getAlgorithm() {
    return "ElGamal";
  }

  /**
   * return the encoding format we produce in getEncoded().
   *
   * @return the string "PKCS#8"
   */
  public String getFormat() {
    return "PKCS#8";
  }

  /**
   * Return a PKCS8 representation of the key. The sequence returned represents a full
   * PrivateKeyInfo object.
   *
   * @return a PKCS8 representation of the key.
   */
  public byte[] getEncoded() {
    return KeyUtil.getEncodedPrivateKeyInfo(
        new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm,
            new ElGamalParameter(elSpec.getP(), elSpec.getG())), new ASN1Integer(getX()));
  }

  public ElGamalParameterSpec getParameters() {
    return elSpec;
  }

  public DHParameterSpec getParams() {
    return new DHParameterSpec(elSpec.getP(), elSpec.getG());
  }

  public BigInteger getX() {
    return x;
  }

  private void readObject(
      ObjectInputStream in)
      throws IOException, ClassNotFoundException {
    x = (BigInteger) in.readObject();

    this.elSpec = new ElGamalParameterSpec((BigInteger) in.readObject(),
        (BigInteger) in.readObject());
  }

  private void writeObject(
      ObjectOutputStream out)
      throws IOException {
    out.writeObject(this.getX());
    out.writeObject(elSpec.getP());
    out.writeObject(elSpec.getG());
  }

  public void setBagAttribute(
      ASN1ObjectIdentifier oid,
      ASN1Encodable attribute) {
    attrCarrier.setBagAttribute(oid, attribute);
  }

  public ASN1Encodable getBagAttribute(
      ASN1ObjectIdentifier oid) {
    return attrCarrier.getBagAttribute(oid);
  }

  public Enumeration getBagAttributeKeys() {
    return attrCarrier.getBagAttributeKeys();
  }
}