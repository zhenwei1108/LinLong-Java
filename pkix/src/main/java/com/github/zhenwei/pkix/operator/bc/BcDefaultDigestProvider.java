package com.github.zhenwei.pkix.operator.bc;

import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.github.zhenwei.core.asn1.gm.GMObjectIdentifiers;
import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.github.zhenwei.core.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.ExtendedDigest;
import com.github.zhenwei.core.crypto.Xof;
import com.github.zhenwei.core.crypto.digests.GOST3411Digest;
import com.github.zhenwei.core.crypto.digests.GOST3411_2012_256Digest;
import com.github.zhenwei.core.crypto.digests.GOST3411_2012_512Digest;
import com.github.zhenwei.core.crypto.digests.MD2Digest;
import com.github.zhenwei.core.crypto.digests.MD4Digest;
import com.github.zhenwei.core.crypto.digests.MD5Digest;
import com.github.zhenwei.core.crypto.digests.RIPEMD128Digest;
import com.github.zhenwei.core.crypto.digests.RIPEMD160Digest;
import com.github.zhenwei.core.crypto.digests.RIPEMD256Digest;
import com.github.zhenwei.core.crypto.digests.SHA1Digest;
import com.github.zhenwei.core.crypto.digests.SHA224Digest;
import com.github.zhenwei.core.crypto.digests.SHA256Digest;
import com.github.zhenwei.core.crypto.digests.SHA384Digest;
import com.github.zhenwei.core.crypto.digests.SHA3Digest;
import com.github.zhenwei.core.crypto.digests.SHA512Digest;
import com.github.zhenwei.core.crypto.digests.SHAKEDigest;
import com.github.zhenwei.core.crypto.digests.SM3Digest;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class BcDefaultDigestProvider
    implements BcDigestProvider {

  private static final Map lookup = createTable();

  private static Map createTable() {
    Map table = new HashMap();

    table.put(OIWObjectIdentifiers.idSHA1, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new SHA1Digest();
      }
    });
    table.put(NISTObjectIdentifiers.id_sha224, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new SHA224Digest();
      }
    });
    table.put(NISTObjectIdentifiers.id_sha256, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new SHA256Digest();
      }
    });
    table.put(NISTObjectIdentifiers.id_sha384, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new SHA384Digest();
      }
    });
    table.put(NISTObjectIdentifiers.id_sha512, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new SHA512Digest();
      }
    });
    table.put(NISTObjectIdentifiers.id_sha3_224, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new SHA3Digest(224);
      }
    });
    table.put(NISTObjectIdentifiers.id_sha3_256, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new SHA3Digest(256);
      }
    });
    table.put(NISTObjectIdentifiers.id_sha3_384, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new SHA3Digest(384);
      }
    });
    table.put(NISTObjectIdentifiers.id_sha3_512, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new SHA3Digest(512);
      }
    });
    table.put(NISTObjectIdentifiers.id_shake128, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new SHAKEDigest(128);
      }
    });
    table.put(NISTObjectIdentifiers.id_shake256, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new SHAKEDigest(256);
      }
    });
    table.put(NISTObjectIdentifiers.id_shake128_len, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new AdjustedXof(new SHAKEDigest(128),
            ASN1Integer.getInstance(digestAlgorithmIdentifier.getParameters()).intValueExact());
      }
    });
    table.put(NISTObjectIdentifiers.id_shake256_len, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new AdjustedXof(new SHAKEDigest(256),
            ASN1Integer.getInstance(digestAlgorithmIdentifier.getParameters()).intValueExact());
      }
    });
    table.put(PKCSObjectIdentifiers.md5, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new MD5Digest();
      }
    });
    table.put(PKCSObjectIdentifiers.md4, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new MD4Digest();
      }
    });
    table.put(PKCSObjectIdentifiers.md2, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new MD2Digest();
      }
    });
    table.put(CryptoProObjectIdentifiers.gostR3411, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new GOST3411Digest();
      }
    });
    table.put(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new GOST3411_2012_256Digest();
      }
    });
    table.put(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new GOST3411_2012_512Digest();
      }
    });
    table.put(TeleTrusTObjectIdentifiers.ripemd128, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new RIPEMD128Digest();
      }
    });
    table.put(TeleTrusTObjectIdentifiers.ripemd160, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new RIPEMD160Digest();
      }
    });
    table.put(TeleTrusTObjectIdentifiers.ripemd256, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new RIPEMD256Digest();
      }
    });
    table.put(GMObjectIdentifiers.sm3, new BcDigestProvider() {
      public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
        return new SM3Digest();
      }
    });

    return Collections.unmodifiableMap(table);
  }

  public static final BcDigestProvider INSTANCE = new BcDefaultDigestProvider();

  private BcDefaultDigestProvider() {

  }

  public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
      throws OperatorCreationException {
    BcDigestProvider extProv = (BcDigestProvider) lookup.get(
        digestAlgorithmIdentifier.getAlgorithm());

    if (extProv == null) {
      throw new OperatorCreationException("cannot recognise digest");
    }

    return extProv.get(digestAlgorithmIdentifier);
  }

  /**
   * -len OIDs for SHAKE include an integer representing the bitlength in of the output.
   */
  private static class AdjustedXof
      implements Xof {

    private final Xof xof;
    private final int length;

    AdjustedXof(Xof xof, int length) {
      this.xof = xof;
      this.length = length;
    }

    public String getAlgorithmName() {
      return xof.getAlgorithmName() + "-" + length;
    }

    public int getDigestSize() {
      return (length + 7) / 8;
    }

    public void update(byte in) {
      xof.update(in);
    }

    public void update(byte[] in, int inOff, int len) {
      xof.update(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff) {
      return doFinal(out, outOff, getDigestSize());
    }

    public void reset() {
      xof.reset();
    }

    public int getByteLength() {
      return xof.getByteLength();
    }

    public int doFinal(byte[] out, int outOff, int outLen) {
      return xof.doFinal(out, outOff, outLen);
    }

    public int doOutput(byte[] out, int outOff, int outLen) {
      return xof.doOutput(out, outOff, outLen);
    }
  }
}