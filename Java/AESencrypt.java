import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

class AES_encrypt {
	public static final int keyLength = 128;
	public static final String charEnc = "UTF-8";
	public static final String transformationString = "AES/CFB/PKCS5PADDING";

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
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
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
			//System.out.println("Encrypted and encoded message is: " + new String(Base64.getEncoder().encode(encrypted), charEnc));
			System.out.println("Encrypted and encoded message is: " +cipherText);

			////////////////////////////////////////////////7

			// Step 1: get the cipher instance.
			Cipher aesCipherForDecryption = Cipher.getInstance(transformationString);

			// Step 2: get the decoded cipher data and the IV (first block)
			cipherData = ByteBuffer.wrap(Base64.getDecoder().decode(cipherText.getBytes(charEnc)));;
			iv = new byte[aesCipherForDecryption.getBlockSize()];
			cipherData.get(iv);
			encrypted = new byte[cipherData.remaining()];
			cipherData.get(encrypted);
			aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

			// Step 3: decrypt the message.
			byte[] decrypted = aesCipherForDecryption.doFinal(encrypted);
			System.out.println("Decrypted text message is: " + new String(decrypted, charEnc));


		} catch(NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | UnsupportedEncodingException ex) {
			System.err.println(ex);
		}
	}

	
}