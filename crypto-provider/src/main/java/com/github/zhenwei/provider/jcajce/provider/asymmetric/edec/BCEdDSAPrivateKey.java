package com.github.zhenwei.provider.jcajce.provider.asymmetric.edec;

import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.edec.EdECObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.Ed25519PrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.Ed448PrivateKeyParameters;
import com.github.zhenwei.core.crypto.util.PrivateKeyInfoFactory;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.core.util.Properties;
import com.github.zhenwei.provider.jcajce.interfaces.EdDSAPrivateKey;
import com.github.zhenwei.provider.jcajce.interfaces.EdDSAPublicKey;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

public class BCEdDSAPrivateKey
    implements EdDSAPrivateKey {

  static final long serialVersionUID = 1L;

  transient AsymmetricKeyParameter eddsaPrivateKey;

  private final boolean hasPublicKey;
  private final byte[] attributes;

  BCEdDSAPrivateKey(AsymmetricKeyParameter privKey) {
    this.hasPublicKey = true;
    this.attributes = null;
    this.eddsaPrivateKey = privKey;
  }

  BCEdDSAPrivateKey(PrivateKeyInfo keyInfo)
      throws IOException {
    this.hasPublicKey = keyInfo.hasPublicKey();
    this.attributes =
        (keyInfo.getAttributes() != null) ? keyInfo.getAttributes().getEncoded() : null;

    populateFromPrivateKeyInfo(keyInfo);
  }

  private void populateFromPrivateKeyInfo(PrivateKeyInfo keyInfo)
      throws IOException {
    byte[] encoding = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();

    if (EdECObjectIdentifiers.id_Ed448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm())) {
      eddsaPrivateKey = new Ed448PrivateKeyParameters(encoding);
    } else {
      eddsaPrivateKey = new Ed25519PrivateKeyParameters(encoding);
    }
  }

  public String getAlgorithm() {
    return (eddsaPrivateKey instanceof Ed448PrivateKeyParameters) ? "Ed448" : "Ed25519";
  }

  public String getFormat() {
    return "PKCS#8";
  }

  public byte[] getEncoded() {
    try {
      ASN1Set attrSet = ASN1Set.getInstance(attributes);
      PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(eddsaPrivateKey,
          attrSet);

      if (hasPublicKey && !Properties.isOverrideSet("com.github.zhenwei.pkix.pkcs8.v1_info_only")) {
        return privInfo.getEncoded();
      } else {
        return new PrivateKeyInfo(privInfo.getPrivateKeyAlgorithm(), privInfo.parsePrivateKey(),
            attrSet).getEncoded();
      }
    } catch (IOException e) {
      return null;
    }
  }

  public EdDSAPublicKey getPublicKey() {
    if (eddsaPrivateKey instanceof Ed448PrivateKeyParameters) {
      return new BCEdDSAPublicKey(
          ((Ed448PrivateKeyParameters) eddsaPrivateKey).generatePublicKey());
    } else {
      return new BCEdDSAPublicKey(
          ((Ed25519PrivateKeyParameters) eddsaPrivateKey).generatePublicKey());
    }
  }

  AsymmetricKeyParameter engineGetKeyParameters() {
    return eddsaPrivateKey;
  }

  public String toString() {
    AsymmetricKeyParameter pubKey;
    if (eddsaPrivateKey instanceof Ed448PrivateKeyParameters) {
      pubKey = ((Ed448PrivateKeyParameters) eddsaPrivateKey).generatePublicKey();
    } else {
      pubKey = ((Ed25519PrivateKeyParameters) eddsaPrivateKey).generatePublicKey();
    }
    return Utils.keyToString("Private Key", getAlgorithm(), pubKey);
  }

  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }

    if (!(o instanceof PrivateKey)) {
      return false;
    }

    PrivateKey other = (PrivateKey) o;

    return Arrays.areEqual(other.getEncoded(), this.getEncoded());
  }

  public int hashCode() {
    return Arrays.hashCode(this.getEncoded());
  }

  private void readObject(
      ObjectInputStream in)
      throws IOException, ClassNotFoundException {
    in.defaultReadObject();

    byte[] enc = (byte[]) in.readObject();

    populateFromPrivateKeyInfo(PrivateKeyInfo.getInstance(enc));
  }

  private void writeObject(
      ObjectOutputStream out)
      throws IOException {
    out.defaultWriteObject();

    out.writeObject(this.getEncoded());
  }
}