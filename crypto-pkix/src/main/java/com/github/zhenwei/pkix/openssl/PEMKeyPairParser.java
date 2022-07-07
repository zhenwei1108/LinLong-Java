package com.github.zhenwei.pkix.openssl;

import java.io.IOException;

interface PEMKeyPairParser {

  PEMKeyPair parse(byte[] encoding)
      throws IOException;
}