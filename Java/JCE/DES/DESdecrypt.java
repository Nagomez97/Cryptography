import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Key;
import java.util.Base64;

class DESdecrypt {
	public static final int keyLength = 56;
	public static final String charEnc = "UTF-8";
	public static final String transformationString = "DES/CBC/PKCS5PADDING";
	public static final String encMode = "DES";

	public static void main(String[] args) {
		String cipherText;
		String encodedKey;
		byte[] keyBytes;
		byte[] encrypted;
		SecretKey secretKey;

		if(args.length < 2){
			System.out.print("Usage: java DESdecrypt [cipherdata] [secret key]\n");
			System.exit(0);
		}

		cipherText = args[0];
		encodedKey = args[1];


		try {
			//Step 1: Get the key and decode it.
			keyBytes = Base64.getDecoder().decode(encodedKey.getBytes(charEnc));
			secretKey = new SecretKeySpec(keyBytes, encMode);

			// Step 2: get the cipher instance.
			Cipher aesCipherForDecryption = Cipher.getInstance(transformationString);

			// Step 3: get the decoded cipher data and the IV (first block)
			ByteBuffer cipherData = ByteBuffer.wrap(Base64.getDecoder().decode(cipherText.getBytes(charEnc)));;
			byte[] iv = new byte[aesCipherForDecryption.getBlockSize()];
			cipherData.get(iv);
			encrypted = new byte[cipherData.remaining()];
			cipherData.get(encrypted);
			aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

			// Step 4: decrypt the message.
			byte[] decrypted = aesCipherForDecryption.doFinal(encrypted);
			System.out.println("Decrypted text message is: " + new String(decrypted, charEnc));

		} catch(NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | UnsupportedEncodingException ex) {
			System.err.println(ex);
		}
	}

	
}