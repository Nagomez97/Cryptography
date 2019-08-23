import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileWriter;
import java.io.IOException;
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
import java.io.FileNotFoundException;
import java.nio.ByteBuffer;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class RSAkeygen {

	public static final int keyLength = 2048;
	public static final String encMode = "RSA";

	public static void main(String[] args){
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(encMode);
			kpg.initialize(keyLength);
			KeyPair kp = kpg.generateKeyPair();
			Key pub = kp.getPublic();
			Key pvt = kp.getPrivate();

			//Exporting keys in binary format
			String outFile = "./RSAkey";
			FileOutputStream out = new FileOutputStream(outFile + ".key");
			out.write(pvt.getEncoded());
			out.close();
			out = new FileOutputStream(outFile + ".pub");
			out.write(pub.getEncoded());
			out.close();

			System.out.println("Private key saved in " + outFile + ".key using format " + pvt.getFormat());
			System.out.println("Public key saved in " + outFile + ".pub using format " + pub.getFormat());
		} catch(IOException | NoSuchAlgorithmException ex){
			System.err.println(ex);
		}
	}

}