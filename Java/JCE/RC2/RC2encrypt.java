import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

class RC2encrypt {
	public static final int keyLength = 512;
	public static final String charEnc = "UTF-8";
	public static final String transformationString = "RC2/CBC/PKCS5PADDING";
	public static final String encMode = "RC2";

	public static void main(String[] args) {
		String message;
		String cipherText;

		if(args.length == 0){
			System.out.print("Message required as an argument.\n");
			System.exit(0);
		}

		message = args[0];

		try {
			// Step 1: generate keyLength-key
			KeyGenerator keyGen = KeyGenerator.getInstance(encMode);
			keyGen.init(keyLength);
			SecretKey secretKey = keyGen.generateKey();

			System.out.println("Symmetric key used: " + new String(Base64.getEncoder().encode(secretKey.getEncoded()), charEnc));

			// Step 2: get the cipher instance with the selected mode
			Cipher aesCipherForEncryption = Cipher.getInstance(transformationString);

			// Step 3: Initialize the IV using a secure random function.
			byte[] iv = new byte[aesCipherForEncryption.getBlockSize()];
			SecureRandom prng = new SecureRandom();
			prng.nextBytes(iv);

			// Step 4
			aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

			// Step 5
			byte[] encrypted = aesCipherForEncryption.doFinal(message.getBytes(charEnc));
			ByteBuffer cipherData = ByteBuffer.allocate(iv.length + encrypted.length);
			cipherData.put(iv);
			cipherData.put(encrypted);
			cipherText = new String(Base64.getEncoder().encode(cipherData.array()), charEnc);
			System.out.println("Encrypted and encoded message is: " + cipherText);


		} catch(NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | UnsupportedEncodingException ex) {
			System.err.println(ex);
		}
	}

	
}