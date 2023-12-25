package crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
	public static byte[] decryptCC20(byte[] cipherBytes, byte[] key, byte[] nonce, int counter) {
		byte[] decryptedBytes = null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("ChaCha20");
			ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, counter);
			SecretKeySpec keySpec = new SecretKeySpec(key, "ChaCha20");
			cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
			decryptedBytes = cipher.doFinal(cipherBytes);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return decryptedBytes;
	}

	public static byte[] decryptAES(String algorithm, byte[] cipherBytes, byte[] keyBytes, byte[] ivBytes) {
		byte[] decryptedBytes = null;
		SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
		IvParameterSpec iv = new IvParameterSpec(ivBytes);

		try {
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
			decryptedBytes = cipher.doFinal(cipherBytes);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return decryptedBytes;
	}

	public static byte[] encryptRSA(String plainText, Cipher encryptCipher, Key publicKey) {
		byte[] cipherBytes = null;
		try {
			byte[] plainBytes = plainText.getBytes();
			encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			cipherBytes = encryptCipher.doFinal(plainBytes);
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return cipherBytes;
	}

	public static byte[] decryptRSA(Key privateKey, byte[] cipherBytes) {
		Cipher decryptCipher = null;
		byte[] decryptedBytes = null;
		try {
			decryptCipher = Cipher.getInstance("RSA");
			decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
			decryptedBytes = decryptCipher.doFinal(cipherBytes);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}
		return decryptedBytes;
	}
}
