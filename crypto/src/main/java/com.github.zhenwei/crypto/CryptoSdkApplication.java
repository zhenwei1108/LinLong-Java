package org.sdk.crypto;

import org.sdk.crypto.init.InitProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CryptoSdkApplication {

	public static void main(String[] args) {
		InitProvider.init();
		SpringApplication.run(CryptoSdkApplication.class, args);
	}

}