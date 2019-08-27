import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.security.SecureRandom;
import java.nio.ByteBuffer;

import javax.crypto.spec.IvParameterSpec;

//import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

class encrypt {
	public static final int keyLength = 256;
	public static final String charEnc = "UTF-8";
	public static final String transformationString = "ChaCha20-Poly1305";
	public static final String encMode = "ChaCha20";



	public static void main(String[] args){
		String message;
		String cipherText;

		if(args.length == 0){
			System.out.print("Message required as an argument.\n");
			System.exit(0);
		}

		message = args[0];

		try {

			// Step 1: generate the key
			KeyGenerator keyGen = KeyGenerator.getInstance(encMode);
			keyGen.init(keyLength);
			SecretKey secretKey = keyGen.generateKey();

			System.out.println("Symmetric key used: " + new String(Base64.getEncoder().encode(secretKey.getEncoded()), charEnc));

			// Step 2: Get the cipher instance with the selected mode
			Cipher cipherForEncryption = Cipher.getInstance(transformationString);

			// Step 3: Initialize the IV using a secure random function.
			byte[] nonce = new byte[12];
			SecureRandom prng = new SecureRandom();
			prng.nextBytes(nonce);

			// Step 4
			cipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(nonce));

			// Step 5
			byte[] encrypted = cipherForEncryption.doFinal(message.getBytes(charEnc));
			ByteBuffer cipherData = ByteBuffer.allocate(nonce.length + encrypted.length);
			cipherData.put(nonce);
			cipherData.put(encrypted);
			cipherText = new String(Base64.getEncoder().encode(cipherData.array()), charEnc);
			System.out.println("Encrypted and encoded message is: " + cipherText);


		} catch(Exception ex){
			System.err.println(ex);
		}



	}
}