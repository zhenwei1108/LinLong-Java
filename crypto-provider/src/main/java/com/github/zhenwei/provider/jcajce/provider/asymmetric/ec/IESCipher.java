package com.github.zhenwei.provider.jcajce.provider.asymmetric.ec;

import com.github.zhenwei.core.crypto.BlockCipher;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.InvalidCipherTextException;
import com.github.zhenwei.core.crypto.KeyEncoder;
import com.github.zhenwei.core.crypto.agreement.ECDHBasicAgreement;
import com.github.zhenwei.core.crypto.engines.AESEngine;
import com.github.zhenwei.core.crypto.engines.DESedeEngine;
import com.github.zhenwei.core.crypto.engines.IESEngine;
import com.github.zhenwei.core.crypto.generators.ECKeyPairGenerator;
import com.github.zhenwei.core.crypto.generators.EphemeralKeyPairGenerator;
import com.github.zhenwei.core.crypto.generators.KDF2BytesGenerator;
import com.github.zhenwei.core.crypto.macs.HMac;
import com.github.zhenwei.core.crypto.modes.CBCBlockCipher;
import com.github.zhenwei.core.crypto.paddings.PaddedBufferedBlockCipher;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.ECDomainParameters;
import com.github.zhenwei.core.crypto.params.ECKeyGenerationParameters;
import com.github.zhenwei.core.crypto.params.ECKeyParameters;
import com.github.zhenwei.core.crypto.params.ECPublicKeyParameters;
import com.github.zhenwei.core.crypto.params.IESWithCipherParameters;
import com.github.zhenwei.core.crypto.params.ParametersWithIV;
import com.github.zhenwei.core.crypto.parsers.ECIESPublicKeyParser;
import com.github.zhenwei.core.crypto.util.DigestFactory;
import com.github.zhenwei.core.math.ec.ECCurve;
import com.github.zhenwei.core.util.Strings;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.util.ECUtil;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.util.IESUtil;
import com.github.zhenwei.provider.jcajce.provider.util.BadBlockException;
import com.github.zhenwei.provider.jcajce.util.BCJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.JcaJceHelper;
import com.github.zhenwei.provider.jce.interfaces.ECKey;
import com.github.zhenwei.provider.jce.interfaces.IESKey;
import com.github.zhenwei.provider.jce.spec.IESParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;


public class IESCipher
    extends CipherSpi {

  private final JcaJceHelper helper = new BCJcaJceHelper();

  private int ivLength;
  private IESEngine engine;
  private int state = -1;
  private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
  private AlgorithmParameters engineParam = null;
  private IESParameterSpec engineSpec = null;
  private AsymmetricKeyParameter key;
  private SecureRandom random;
  private boolean dhaesMode = false;
  private AsymmetricKeyParameter otherKeyParameter = null;

  public IESCipher(IESEngine engine) {
    this.engine = engine;
    this.ivLength = 0;
  }

  public IESCipher(IESEngine engine, int ivLength) {
    this.engine = engine;
    this.ivLength = ivLength;
  }

  public int engineGetBlockSize() {
    if (engine.getCipher() != null) {
      return engine.getCipher().getBlockSize();
    } else {
      return 0;
    }
  }


  public int engineGetKeySize(Key key) {
    if (key instanceof ECKey) {
      return ((ECKey) key).getParameters().getCurve().getFieldSize();
    } else {
      throw new IllegalArgumentException("not an EC key");
    }
  }


  public byte[] engineGetIV() {
    if (engineSpec != null) {
      return engineSpec.getNonce();
    }
    return null;
  }

  public AlgorithmParameters engineGetParameters() {
    if (engineParam == null && engineSpec != null) {
      try {
        engineParam = helper.createAlgorithmParameters("IES");
        engineParam.init(engineSpec);
      } catch (Exception e) {
        throw new RuntimeException(e.toString());
      }
    }

    return engineParam;
  }


  public void engineSetMode(String mode)
      throws NoSuchAlgorithmException {
    String modeName = Strings.toUpperCase(mode);

    if (modeName.equals("NONE")) {
      dhaesMode = false;
    } else if (modeName.equals("DHAES")) {
      dhaesMode = true;
    } else {
      throw new IllegalArgumentException("can't support mode " + mode);
    }
  }


  public int engineGetOutputSize(int inputLen) {
    int len1, len2, len3;

    if (key == null) {
      throw new IllegalStateException("cipher not initialised");
    }

    len1 = engine.getMac().getMacSize();

    if (otherKeyParameter == null) {
      ECCurve c = ((ECKeyParameters) key).getParameters().getCurve();
      int feSize = (c.getFieldSize() + 7) / 8;
      len2 = 2 * feSize;
    } else {
      len2 = 0;
    }

    int inLen = buffer.size() + inputLen;
    if (engine.getCipher() == null) {
      len3 = inLen;
    } else if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE) {
      len3 = engine.getCipher().getOutputSize(inLen);
    } else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE) {
      len3 = engine.getCipher().getOutputSize(inLen - len1 - len2);
    } else {
      throw new IllegalStateException("cipher not initialised");
    }

    if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE) {
      return len1 + len2 + len3;
    } else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE) {
      return len3;
    } else {
      throw new IllegalStateException("cipher not initialised");
    }
  }

  public void engineSetPadding(String padding)
      throws NoSuchPaddingException {
    String paddingName = Strings.toUpperCase(padding);

    // TDOD: make this meaningful...
    if (paddingName.equals("NOPADDING")) {

    } else if (paddingName.equals("PKCS5PADDING") || paddingName.equals("PKCS7PADDING")) {

    } else {
      throw new NoSuchPaddingException("padding not available with IESCipher");
    }
  }

  // Initialisation methods

  public void engineInit(
      int opmode,
      Key key,
      AlgorithmParameters params,
      SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    AlgorithmParameterSpec paramSpec = null;

    if (params != null) {
      try {
        paramSpec = params.getParameterSpec(IESParameterSpec.class);
      } catch (Exception e) {
        throw new InvalidAlgorithmParameterException(
            "cannot recognise parameters: " + e.toString());
      }
    }

    engineParam = params;
    engineInit(opmode, key, paramSpec, random);

  }


  public void engineInit(
      int opmode,
      Key key,
      AlgorithmParameterSpec engineSpec,
      SecureRandom random)
      throws InvalidAlgorithmParameterException, InvalidKeyException {
    otherKeyParameter = null;

    // Use default parameters (including cipher key size) if none are specified
    if (engineSpec == null) {
      byte[] nonce = null;
      if (ivLength != 0 && opmode == Cipher.ENCRYPT_MODE) {
        nonce = new byte[ivLength];
        random.nextBytes(nonce);
      }
      this.engineSpec = IESUtil.guessParameterSpec(engine.getCipher(), nonce);
    } else if (engineSpec instanceof IESParameterSpec) {
      this.engineSpec = (IESParameterSpec) engineSpec;
    } else {
      throw new InvalidAlgorithmParameterException("must be passed IES parameters");
    }

    byte[] nonce = this.engineSpec.getNonce();

    if (ivLength != 0 && (nonce == null || nonce.length != ivLength)) {
      throw new InvalidAlgorithmParameterException(
          "NONCE in IES Parameters needs to be " + ivLength + " bytes long");
    }

    // Parse the recipient's key
    if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
      if (key instanceof PublicKey) {
        this.key = ECUtils.generatePublicKeyParameter((PublicKey) key);
      } else if (key instanceof IESKey) {
        IESKey ieKey = (IESKey) key;

        this.key = ECUtils.generatePublicKeyParameter(ieKey.getPublic());
        this.otherKeyParameter = ECUtil.generatePrivateKeyParameter(ieKey.getPrivate());
      } else {
        throw new InvalidKeyException("must be passed recipient's public EC key for encryption");
      }
    } else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
      if (key instanceof PrivateKey) {
        this.key = ECUtil.generatePrivateKeyParameter((PrivateKey) key);
      } else if (key instanceof IESKey) {
        IESKey ieKey = (IESKey) key;

        this.otherKeyParameter = ECUtils.generatePublicKeyParameter(ieKey.getPublic());
        this.key = ECUtil.generatePrivateKeyParameter(ieKey.getPrivate());
      } else {
        throw new InvalidKeyException("must be passed recipient's private EC key for decryption");
      }
    } else {
      throw new InvalidKeyException("must be passed EC key");
    }

    this.random = random;
    this.state = opmode;
    buffer.reset();

  }


  public void engineInit(
      int opmode,
      Key key,
      SecureRandom random)
      throws InvalidKeyException {
    try {
      engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException(
          "cannot handle supplied parameter spec: " + e.getMessage());
    }

  }

  // Update methods - buffer the input

  public byte[] engineUpdate(
      byte[] input,
      int inputOffset,
      int inputLen) {
    buffer.write(input, inputOffset, inputLen);
    return null;
  }


  public int engineUpdate(
      byte[] input,
      int inputOffset,
      int inputLen,
      byte[] output,
      int outputOffset) {
    buffer.write(input, inputOffset, inputLen);
    return 0;
  }

  // Finalisation methods

  public byte[] engineDoFinal(
      byte[] input,
      int inputOffset,
      int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    if (inputLen != 0) {
      buffer.write(input, inputOffset, inputLen);
    }

    final byte[] in = buffer.toByteArray();
    buffer.reset();

    // Convert parameters for use in IESEngine
    CipherParameters params = new IESWithCipherParameters(engineSpec.getDerivationV(),
        engineSpec.getEncodingV(),
        engineSpec.getMacKeySize(),
        engineSpec.getCipherKeySize());

    if (engineSpec.getNonce() != null) {
      params = new ParametersWithIV(params, engineSpec.getNonce());
    }

    final ECDomainParameters ecParams = ((ECKeyParameters) key).getParameters();

    final byte[] V;

    if (otherKeyParameter != null) {
      try {
        if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE) {
          engine.init(true, otherKeyParameter, key, params);
        } else {
          engine.init(false, key, otherKeyParameter, params);
        }
        return engine.processBlock(in, 0, in.length);
      } catch (Exception e) {
        throw new BadBlockException("unable to process block", e);
      }
    }

    if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE) {
      // Generate the ephemeral key pair
      ECKeyPairGenerator gen = new ECKeyPairGenerator();
      gen.init(new ECKeyGenerationParameters(ecParams, random));

      final boolean usePointCompression = engineSpec.getPointCompression();
      EphemeralKeyPairGenerator kGen = new EphemeralKeyPairGenerator(gen, new KeyEncoder() {
        public byte[] getEncoded(AsymmetricKeyParameter keyParameter) {
          return ((ECPublicKeyParameters) keyParameter).getQ().getEncoded(usePointCompression);
        }
      });

      // Encrypt the buffer
      try {
        engine.init(key, params, kGen);

        return engine.processBlock(in, 0, in.length);
      } catch (final Exception e) {
        throw new BadBlockException("unable to process block", e);
      }
    } else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE) {
      // Decrypt the buffer
      try {
        engine.init(key, params, new ECIESPublicKeyParser(ecParams));

        return engine.processBlock(in, 0, in.length);
      } catch (InvalidCipherTextException e) {
        throw new BadBlockException("unable to process block", e);
      }
    } else {
      throw new IllegalStateException("cipher not initialised");
    }

  }

  public int engineDoFinal(
      byte[] input,
      int inputOffset,
      int inputLength,
      byte[] output,
      int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {

    byte[] buf = engineDoFinal(input, inputOffset, inputLength);

    System.arraycopy(buf, 0, output, outputOffset, buf.length);
    return buf.length;
  }

  /**
   * Classes that inherit from us
   */

  static public class ECIES
      extends IESCipher {

    public ECIES() {
      this(DigestFactory.createSHA1(), DigestFactory.createSHA1());
    }

    public ECIES(Digest kdfDigest, Digest macDigest) {
      super(new IESEngine(new ECDHBasicAgreement(),
          new KDF2BytesGenerator(kdfDigest),
          new HMac(macDigest)));
    }
  }

  static public class ECIESwithSHA256
      extends ECIES {

    public ECIESwithSHA256() {
      super(DigestFactory.createSHA256(), DigestFactory.createSHA256());
    }
  }

  static public class ECIESwithSHA384
      extends ECIES {

    public ECIESwithSHA384() {
      super(DigestFactory.createSHA384(), DigestFactory.createSHA384());
    }
  }

  static public class ECIESwithSHA512
      extends ECIES {

    public ECIESwithSHA512() {
      super(DigestFactory.createSHA512(), DigestFactory.createSHA512());
    }
  }

  static public class ECIESwithCipher
      extends IESCipher {

    public ECIESwithCipher(BlockCipher cipher, int ivLength) {
      this(cipher, ivLength, DigestFactory.createSHA1(), DigestFactory.createSHA1());
    }

    public ECIESwithCipher(BlockCipher cipher, int ivLength, Digest kdfDigest, Digest macDigest) {
      super(new IESEngine(new ECDHBasicAgreement(),
          new KDF2BytesGenerator(kdfDigest),
          new HMac(macDigest),
          new PaddedBufferedBlockCipher(cipher)), ivLength);
    }
  }

  static public class ECIESwithDESedeCBC
      extends ECIESwithCipher {

    public ECIESwithDESedeCBC() {
      super(new CBCBlockCipher(new DESedeEngine()), 8);
    }
  }

  static public class ECIESwithSHA256andDESedeCBC
      extends ECIESwithCipher {

    public ECIESwithSHA256andDESedeCBC() {
      super(new CBCBlockCipher(new DESedeEngine()), 8, DigestFactory.createSHA256(),
          DigestFactory.createSHA256());
    }
  }

  static public class ECIESwithSHA384andDESedeCBC
      extends ECIESwithCipher {

    public ECIESwithSHA384andDESedeCBC() {
      super(new CBCBlockCipher(new DESedeEngine()), 8, DigestFactory.createSHA384(),
          DigestFactory.createSHA384());
    }
  }

  static public class ECIESwithSHA512andDESedeCBC
      extends ECIESwithCipher {

    public ECIESwithSHA512andDESedeCBC() {
      super(new CBCBlockCipher(new DESedeEngine()), 8, DigestFactory.createSHA512(),
          DigestFactory.createSHA512());
    }
  }

  static public class ECIESwithAESCBC
      extends ECIESwithCipher {

    public ECIESwithAESCBC() {
      super(new CBCBlockCipher(new AESEngine()), 16);
    }
  }

  static public class ECIESwithSHA256andAESCBC
      extends ECIESwithCipher {

    public ECIESwithSHA256andAESCBC() {
      super(new CBCBlockCipher(new AESEngine()), 16, DigestFactory.createSHA256(),
          DigestFactory.createSHA256());
    }
  }

  static public class ECIESwithSHA384andAESCBC
      extends ECIESwithCipher {

    public ECIESwithSHA384andAESCBC() {
      super(new CBCBlockCipher(new AESEngine()), 16, DigestFactory.createSHA384(),
          DigestFactory.createSHA384());
    }
  }

  static public class ECIESwithSHA512andAESCBC
      extends ECIESwithCipher {

    public ECIESwithSHA512andAESCBC() {
      super(new CBCBlockCipher(new AESEngine()), 16, DigestFactory.createSHA512(),
          DigestFactory.createSHA512());
    }
  }
}