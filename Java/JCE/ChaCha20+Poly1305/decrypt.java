import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import java.nio.ByteBuffer;

import java.security.SecureRandom;
import java.security.Key;
import java.util.Base64;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.Security;

import javax.crypto.spec.IvParameterSpec;

class decrypt {
	public static final int keyLength = 256;
	public static final String charEnc = "UTF-8";
	public static final String transformationString = "ChaCha20-Poly1305";
	public static final String encMode = "ChaCha20";

	public static void main(String[] args) {
		String cipherText;
		String encodedKey;
		byte[] keyBytes;
		byte[] encrypted;
		SecretKey secretKey;

		if(args.length < 2){
			System.out.print("Usage: java decrypt [cipherdata] [secret key]\n");
			System.exit(0);
		}

		cipherText = args[0];
		encodedKey = args[1];


		try {

			//Step 1: Get the key and decode it.
			keyBytes = Base64.getDecoder().decode(encodedKey.getBytes(charEnc));
			secretKey = new SecretKeySpec(keyBytes, encMode);

			// Step 2: get the cipher instance.
			Cipher cipherForDecryption = Cipher.getInstance(transformationString);

			// Step 3: get the decoded cipher data and the IV (first block)
			ByteBuffer cipherData = ByteBuffer.wrap(Base64.getDecoder().decode(cipherText.getBytes(charEnc)));
			byte[] nonce = new byte[12];
			cipherData.get(nonce); 
			encrypted = new byte[cipherData.remaining()];
			cipherData.get(encrypted);
			cipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(nonce));
			
			// Step 4: decrypt the message.
			byte[] decrypted = cipherForDecryption.doFinal(encrypted);

			String decryptedText = new String(decrypted, charEnc);
			System.out.println("Decrypted text message is: " + decryptedText);

		} catch(Exception ex) {
			System.err.println(ex);
		}
	}

	
}