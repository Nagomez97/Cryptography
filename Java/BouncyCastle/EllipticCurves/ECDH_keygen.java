import java.util.Arrays;
import java.io.*;
import java.security.Key;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Base64;

class ECDHkeygen {
	public static final String curveName = "prime192v1";

	public static void main(String[] args){
		try {

			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
			KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
			g.initialize(ecSpec, new SecureRandom());
			KeyPair kp = g.generateKeyPair();

			KeyFactory fact = KeyFactory.getInstance("ECDH", "BC");
			PublicKey pub_enc = fact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
			PrivateKey pvt_enc = fact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

			//Exporting keys in binary format
			Base64.Encoder encoder = Base64.getEncoder();
			String outFile = "./ECDHkey";
			FileWriter fileWriter = new FileWriter(outFile + ".key");
			PrintWriter out = new PrintWriter(fileWriter);
			out.println(encoder.encodeToString(pvt_enc.getEncoded()));
			out.close();
			fileWriter = new FileWriter(outFile + ".pub");
			out = new PrintWriter(fileWriter);
			out.println(encoder.encodeToString(pub_enc.getEncoded()));
			out.close();


		} catch (Exception ex){
			System.err.println(ex);
		}
	}
}