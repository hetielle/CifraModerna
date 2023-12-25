package application;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import crypto.Crypto;

public class Main {

	public static void main(String[] args) {
		String keyText = "Wbbkvdr7TNZsQNQdSNU8yBGpJSwBPhxuIl6aWGvYgpA="; // Chave para usar o AES
		String ivText = "s1FVuvULeR5JRzCse+ekXg==";
		String nonceText = "4lsAbSefUo+iPd7W";
		String cipherKeyText = "rcZPzZ8wnG48IIdi+mY6MHlfiGbSYH/rwJTVxTAVocQyBZqlLtcl6co7BBLZVLtq"; // Chave
																									// criptografada
		String algorithm = "AES/CBC/PKCS5Padding";

		// Passando p/ bytes[] e decifrando
		byte[] cipherKeyBytes = Base64.getDecoder().decode(cipherKeyText);
		byte[] keyBytes = Base64.getDecoder().decode(keyText);
		byte[] ivBytes = Base64.getDecoder().decode(ivText);
		byte[] nonceBytes = Base64.getDecoder().decode(nonceText);
		byte[] decryptedKeyBytes = Crypto.decryptAES(algorithm, cipherKeyBytes, keyBytes, ivBytes);

		// Transformando arquivo em bytes[] e descriptografando
		Path directory = Paths.get("/home/alunoinfo/Downloads/file.enc");
		byte[] text;
		try {
			text = Files.readAllBytes(directory);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		byte[] decryptedFileBytes = Crypto.decryptCC20(text, decryptedKeyBytes, nonceBytes, 0);

		// Transformando arquivo de bytes[] p/ .txt
		try (FileOutputStream fos = new FileOutputStream("/home/alunoinfo/Desktop/final.txt")) {
			fos.write(decryptedFileBytes);
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		
		
		///////////////////////////////////////////////////////////////////////////////////////////////////////////
		try {
			// keys
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			KeyPair pair = generator.generateKeyPair();
			PrivateKey privateKey = pair.getPrivate();
			PublicKey publicKey = pair.getPublic();
			// config
			Cipher encryptCipher = Cipher.getInstance("RSA");

			// salvar chave em arquivo
			FileOutputStream fosPu = new FileOutputStream("public.key");
			fosPu.write(publicKey.getEncoded());
			FileOutputStream fosPr = new FileOutputStream("private.key");
			fosPr.write(privateKey.getEncoded());

			// carregar chave publica de arquivo
			KeyFactory keyFactoryArchive = KeyFactory.getInstance("RSA");
			File publicKeyFile = new File("public.key");
			byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
			PublicKey publicKeyArchive = keyFactoryArchive.generatePublic(publicKeySpec);

			// carregar chave privada de arquivo
			KeyFactory keyFactoryArchive2 = KeyFactory.getInstance("RSA");
			File privateKeyFile = new File("private.key");
			byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			PrivateKey privateKeyArchive = keyFactoryArchive2.generatePrivate(privateKeySpec);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException
				| IOException | InvalidKeySpecException e) {
			e.printStackTrace();
		}

	}

}
