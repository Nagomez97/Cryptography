import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Base64;
import java.util.Arrays;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.nio.ByteBuffer;


public class RSAdecrypt {
	public static final String encMode = "AES";
	public static final int symmetricKeyLength = 256;
	public static final String keyFile = "./RSAkey";
	public static final String charEnc = "UTF-8";
	public static final String cipherInstance = "RSA/ECB/PKCS1Padding";
	public static final String transformationString = "AES/CFB/PKCS5PADDING";


	public static void main(String[] args){
		String cipherText;
		String encodedSecretKey;
		byte[] keyBytes;
		byte[] encrypted;

		if(args.length < 2){
			System.out.print("Usage: java RSAdecrypt [ciphertext] [AES encrypted secret key]\n");
			System.exit(0);
		}

		cipherText = args[0];
		encodedSecretKey = args[1];

		try {

			//Loading RSA public key
			byte[] bytes = Files.readAllBytes(Paths.get(keyFile + ".key"));
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey pvt = kf.generatePrivate(ks);

			Cipher cipher = Cipher.getInstance(cipherInstance);
			cipher.init(Cipher.DECRYPT_MODE, pvt);

			//Decrypting AES secret key using public key
			keyBytes = Base64.getDecoder().decode(encodedSecretKey.getBytes(charEnc));
			SecretKey skey = new SecretKeySpec(cipher.doFinal(keyBytes), "AES");



			//AES decryption
			Cipher aesCipherForDecryption = Cipher.getInstance(transformationString);

			ByteBuffer cipherData = ByteBuffer.wrap(Base64.getDecoder().decode(cipherText.getBytes(charEnc)));
			byte[] iv = new byte[128/8];
			cipherData.get(iv);
			encrypted = new byte[cipherData.remaining()];
			cipherData.get(encrypted);
			aesCipherForDecryption.init(Cipher.DECRYPT_MODE, skey, new IvParameterSpec(iv));

			byte[] decrypted = aesCipherForDecryption.doFinal(encrypted);
			System.out.println("Decrypted text message is: " + new String(decrypted, charEnc));
			

		} catch(Exception ex){
			System.err.println(ex);
		}

	}

}