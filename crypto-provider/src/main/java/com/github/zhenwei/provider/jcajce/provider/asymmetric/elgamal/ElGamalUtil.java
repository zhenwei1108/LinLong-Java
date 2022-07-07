package com.github.zhenwei.provider.jcajce.provider.asymmetric.elgamal;

import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.ElGamalParameters;
import com.github.zhenwei.core.crypto.params.ElGamalPrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.ElGamalPublicKeyParameters;
import com.github.zhenwei.provider.jce.interfaces.ElGamalPrivateKey;
import com.github.zhenwei.provider.jce.interfaces.ElGamalPublicKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

/**
 * utility class for converting jce/jca ElGamal objects objects into their
 * com.github.zhenwei.core.crypto counterparts.
 */
public class ElGamalUtil {

  static public AsymmetricKeyParameter generatePublicKeyParameter(
      PublicKey key)
      throws InvalidKeyException {
    if (key instanceof ElGamalPublicKey) {
      ElGamalPublicKey k = (ElGamalPublicKey) key;

      return new ElGamalPublicKeyParameters(k.getY(),
          new ElGamalParameters(k.getParameters().getP(), k.getParameters().getG()));
    } else if (key instanceof DHPublicKey) {
      DHPublicKey k = (DHPublicKey) key;

      return new ElGamalPublicKeyParameters(k.getY(),
          new ElGamalParameters(k.getParams().getP(), k.getParams().getG()));
    }

    throw new InvalidKeyException("can't identify public key for El Gamal.");
  }

  static public AsymmetricKeyParameter generatePrivateKeyParameter(
      PrivateKey key)
      throws InvalidKeyException {
    if (key instanceof ElGamalPrivateKey) {
      ElGamalPrivateKey k = (ElGamalPrivateKey) key;

      return new ElGamalPrivateKeyParameters(k.getX(),
          new ElGamalParameters(k.getParameters().getP(), k.getParameters().getG()));
    } else if (key instanceof DHPrivateKey) {
      DHPrivateKey k = (DHPrivateKey) key;

      return new ElGamalPrivateKeyParameters(k.getX(),
          new ElGamalParameters(k.getParams().getP(), k.getParams().getG()));
    }

    throw new InvalidKeyException("can't identify private key for El Gamal.");
  }
}