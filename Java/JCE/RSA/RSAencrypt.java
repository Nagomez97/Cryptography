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


public class RSAencrypt {
	public static final String encMode = "AES";
	public static final int symmetricKeyLength = 256;
	public static final String keyFile = "./RSAkey";
	public static final String charEnc = "UTF-8";
	public static final String cipherInstance = "RSA/ECB/PKCS1Padding";
	public static final String transformationString = "AES/CFB/PKCS5PADDING";


	public static void main(String[] args){
		String message;

		if(args.length == 0){
			System.out.print("Message required as an argument.\n");
			System.exit(0);
		}

		message = args[0];

		try {
			//Generating AES key and IV
			KeyGenerator kgen = KeyGenerator.getInstance(encMode);
			kgen.init(symmetricKeyLength);
			SecretKey skey = kgen.generateKey();
			String cipherText;

			SecureRandom srandom = new SecureRandom();
			byte[] iv = new byte[symmetricKeyLength/8];
			srandom.nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			//Loading RSA key and encrypting secret key
			byte[] bytes = Files.readAllBytes(Paths.get(keyFile + ".pub"));
			X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey pub = kf.generatePublic(ks);

			Cipher cipher = Cipher.getInstance(cipherInstance);
			cipher.init(Cipher.ENCRYPT_MODE, pub);

			byte[] b = cipher.doFinal(skey.getEncoded());

			System.out.println("Symmetric key used (encrypted): " + new String(Base64.getEncoder().encode(b), charEnc));


			//AES encryption
			Cipher aesCipherForEncryption = Cipher.getInstance(transformationString);

			iv = new byte[aesCipherForEncryption.getBlockSize()];
			SecureRandom prng = new SecureRandom();
			prng.nextBytes(iv);

			aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, skey, new IvParameterSpec(iv));

			byte[] encrypted = aesCipherForEncryption.doFinal(message.getBytes(charEnc));
			ByteBuffer cipherData = ByteBuffer.allocate(iv.length + encrypted.length);
			cipherData.put(iv);
			cipherData.put(encrypted);
			cipherText = new String(Base64.getEncoder().encode(cipherData.array()), charEnc);
			System.out.println("Encrypted and encoded message is: " + cipherText);

		} catch(Exception ex){
			System.err.println(ex);
		}

	}

}