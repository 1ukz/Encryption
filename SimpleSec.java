import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class SimpleSec {

	private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final String RSA_ALGORITHM = "RSA";
	private static final String PRIVATE_KEY_FILE = "./private.key";
	private static final String PUBLIC_KEY_FILE = "./public.key";

	private RSALibrary rsaLibrary = new RSALibrary();

	// generar claves RSA y proteger la clave privada con una passphrase
	public void generateAndProtectKeys(String passphrase) throws Exception {
		rsaLibrary.generateKeys();

		// cargar la clave privada generada
		byte[] bytes = Files.readAllBytes(new File(PRIVATE_KEY_FILE).toPath());
		PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(bytes);
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyfactory.generatePrivate(keyspec);

		// cifrar la clave privada usando la passphrase proporcionada
		byte[] encryptedPrivateKey = encryptPrivateKeyWithPassphrase(privateKey.getEncoded(), passphrase);

		// guardar la clave privada cifrada
		try (FileOutputStream fos = new FileOutputStream(PRIVATE_KEY_FILE)) {
			fos.write(encryptedPrivateKey);
		}
		System.out.println("Keys have been generated and the private key has been encrypted with the passphrase.");
	}

	// cargar la clave privada descifrándola con la passphrase
	private PrivateKey loadPrivateKeyWithPassphrase(String passphrase) throws Exception {
		byte[] encryptedPrivateKey = Files.readAllBytes(new File(PRIVATE_KEY_FILE).toPath());

		// descifrar la clave privada usando la passphrase
		byte[] privateKeyBytes = decryptPrivateKeyWithPassphrase(encryptedPrivateKey, passphrase);

		// reconstruir la clave privada desde los bytes
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		return keyFactory.generatePrivate(keySpec);
	}

	// cifrar la clave privada con AES y la passphrase
	private byte[] encryptPrivateKeyWithPassphrase(byte[] privateKeyBytes, String passphrase) throws Exception {
		Cipher cipher = Cipher.getInstance(AES_ALGORITHM);

		// aseguramos que la clave AES sea de 16 bytes (128 bits)
		byte[] keyBytes = Arrays.copyOf(passphrase.getBytes("UTF-8"), 16);
		SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

		// generar un IV
		byte[] iv = new byte[16];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		IvParameterSpec ivParams = new IvParameterSpec(iv);

		// cifrar los bytes de la clave privada
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
		byte[] encryptedPrivateKey = cipher.doFinal(privateKeyBytes);

		// concatenar el IV al principio de los datos cifrados
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(iv);
		outputStream.write(encryptedPrivateKey);
		return outputStream.toByteArray();
	}

	// descifrar la clave privada con AES y la passphrase
	private byte[] decryptPrivateKeyWithPassphrase(byte[] encryptedPrivateKey, String passphrase) throws Exception {
		Cipher cipher = Cipher.getInstance(AES_ALGORITHM);

		// aseguramos que la clave AES sea de 16 bytes (128 bits)
		byte[] keyBytes = Arrays.copyOf(passphrase.getBytes("UTF-8"), 16);
		SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

		// extraer el IV de los primeros 16 bytes
		byte[] iv = Arrays.copyOfRange(encryptedPrivateKey, 0, 16);
		IvParameterSpec ivParams = new IvParameterSpec(iv);

		// el resto son los datos cifrados
		byte[] encryptedBytes = Arrays.copyOfRange(encryptedPrivateKey, 16, encryptedPrivateKey.length);

		// descifrar los datos
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
		return cipher.doFinal(encryptedBytes);
	}

	// cifrar y firmar el archivo
	public void encryptAndSign(String sourceFile, String destFile, String passphrase) throws Exception {
		// cargar la clave publica
		byte[] bytes = Files.readAllBytes(new File(PUBLIC_KEY_FILE).toPath());
		X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes);
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyfactory.generatePublic(keyspec);

		// cargar la clave privada
		PrivateKey privateKey = loadPrivateKeyWithPassphrase(passphrase);

		// leer el contenido del archivo fuente
		byte[] fileContent = Files.readAllBytes(new File(sourceFile).toPath());

		// cifrar el archivo usando AES
		byte[] aesKey = new byte[16]; // 16 bytes para AES-128
		SecureRandom random = new SecureRandom();
		random.nextBytes(aesKey);


		// cifrar el contenido del archivo
		SymmetricCipher sc = new SymmetricCipher();
		byte[] encryptedFileContent = sc.encryptCBC(fileContent, aesKey);

		// cifrar la clave AES con la clave pública RSA
		byte[] encryptedAESKey = rsaLibrary.encrypt(aesKey, publicKey);

		// firmar el archivo cifrado con la clave privada
		byte[] signature = rsaLibrary.sign(encryptedFileContent, privateKey);

		// guardar en el archivo destino (clave AES cifrada, archivo cifrado, firma)
		try (FileOutputStream fos = new FileOutputStream(destFile)) {
			fos.write(encryptedAESKey);
			fos.write(encryptedFileContent);
			fos.write(signature);
		}
		System.out.println("File encrypted and signed succesfully.");
	}

	// descifrar y verificar el archivo
	public void decryptAndVerify(String sourceFile, String destFile, String passphrase) throws Exception {
		// cargar la clave privada
		PrivateKey privateKey = loadPrivateKeyWithPassphrase(passphrase);

		// cargar la clave pública
		byte[] bytes = Files.readAllBytes(new File(PUBLIC_KEY_FILE).toPath());
		X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes);
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyfactory.generatePublic(keyspec);

		// leer el contenido del archivo fuente
		byte[] fileContent = Files.readAllBytes(new File(sourceFile).toPath());

		// verifica que el archivo tenga el tamaño esperado
		if (fileContent.length < 256) { // 128 (clave AES cifrada) + 128 (firma)
			throw new IllegalArgumentException("The file does not have the expected size.");
		}

		// extraer la clave AES cifrada y el contenido cifrado
		byte[] encryptedAESKey = Arrays.copyOfRange(fileContent, 0, 128); // Clave AES cifrada
		byte[] encryptedFileContent = Arrays.copyOfRange(fileContent, 128, fileContent.length - 128); // Contenido
																										// cifrado
		byte[] signature = Arrays.copyOfRange(fileContent, fileContent.length - 128, fileContent.length); // Firma (128
																											// bytes)

		// descifrar la clave AES usando la clave privada RSA
		byte[] aesKey = rsaLibrary.decrypt(encryptedAESKey, privateKey);

		// verificar la firma
		boolean isVerified = rsaLibrary.verify(encryptedFileContent, signature, publicKey);
		if (!isVerified) {
			throw new SecurityException("Signature could not be verified.");
		}

		// descifrar el contenido del archivo
		SymmetricCipher sc = new SymmetricCipher();
		byte[] decryptedFileContent = sc.decryptCBC(encryptedFileContent, aesKey);

		// guardar el contenido descifrado en el archivo destino
		try (FileOutputStream fos = new FileOutputStream(destFile)) {
			fos.write(decryptedFileContent);
		}
		System.out.println("File unencrypted and verified succesfully.");
	}

	public static void main(String[] args) throws Exception {
		SimpleSec simpleSec = new SimpleSec();
		try {
			if (args.length < 1) {
				System.out.println("Usage: java SimpleSec command [sourceFile] [destinationFile]");
				return;
			}

			switch (args[0]) {
			case "g":
				System.out.print("Enter the passphrase: ");
				String passphrase = new BufferedReader(new InputStreamReader(System.in)).readLine();
				if (passphrase.length() != 16) {
					throw new Exception("Key size is incorrect. Remember it should be 16 bytes (16 characters ASCII)");
				}
				simpleSec.generateAndProtectKeys(passphrase);
				break;
			case "e":
				if (args.length < 3) {
					System.out.println("Usage: java SimpleSec e [sourceFile] [destinationFile]");
					return;
				}
				SimpleSec sSecE = new SimpleSec();
				System.out.println("Enter your passphrase to retrieve the private key:");
				String passphraseE = new BufferedReader(new InputStreamReader(System.in)).readLine();
				sSecE.encryptAndSign(args[1], args[2], passphraseE);
				break;
			case "d":
				if (args.length < 3) {
					System.out.println("Usage: java SimpleSec d [sourceFile] [destinationFile]");
					return;
				}
				SimpleSec sSecD = new SimpleSec();
				System.out.println("Enter your passphrase to retrieve the private key:");
				String passphraseD = new BufferedReader(new InputStreamReader(System.in)).readLine();
				sSecD.decryptAndVerify(args[1], args[2], passphraseD);
				break;

			default:
				System.out.println(
						"Invalid command. Use 'g' for generate, 'e' for encrypt and sign, or 'd' for decrypt and verify.");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
