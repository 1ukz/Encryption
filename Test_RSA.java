import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class Test_RSA {
	
	public static void main(String[] args) throws Exception {
		
		/* ENCRIPTACION SIMETRICA */
		
		byte[] key = "31323334353637383930313233343536".getBytes();  // clave AES de 16 bytes
        SymmetricCipher cipher = new SymmetricCipher();

        
        System.out.println(".....MESSAGE.....");
		byte[] message = "Hola mundooo!".getBytes(); // Texto de prueba
        
        System.out.println("Plain text message: " + new String (message));
        System.out.println("Length of plain text message: " + message.length);
                
        System.out.println("......ENCRYPTION.....");
        byte[] encrypted = cipher.encryptCBC(message, key);
        System.out.println("Encrypted: " + new String(encrypted));  
        String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted); 
        System.out.println("Encrypted (Base64): " + encryptedBase64);
        System.out.println("Length of encrypted text message:"  + encrypted.length);

        System.out.println(".....DECRYPTION.....");
        byte[] decrypted = cipher.decryptCBC(encrypted, key);
        System.out.println("Decrypted: " + new String(decrypted));  
        
        System.out.println(".....MESSAGE.....");
		byte[] message2 = "Hola esto es un mensaje mas largo para ver si funciona bien mi codigo!".getBytes(); // Texto de prueba
        
        System.out.println("Plain text message: " + new String (message2));
        System.out.println("Length of plain text message: " + message2.length);
                
        System.out.println("......ENCRYPTION.....");
        byte[] encrypted2 = cipher.encryptCBC(message2, key);
        System.out.println("Encrypted: " + new String(encrypted2));  
        String encryptedBase64_2 = Base64.getEncoder().encodeToString(encrypted2); 
        System.out.println("Encrypted (Base64): " + encryptedBase64_2);
        System.out.println("Length of encrypted text message:"  + encrypted2.length);

        System.out.println(".....DECRYPTION.....");
        byte[] decrypted2 = cipher.decryptCBC(encrypted2, key);
        System.out.println("Decrypted: " + new String(decrypted2));  
		
		/* ENCRIPTACION ASIMETRICA */
		RSALibrary r = new RSALibrary();
		r.generateKeys();
		
		/* Read  public key*/
		Path path = Paths.get("./public.key");
		byte[] bytes = Files.readAllBytes(path);
		//Public key is stored in x509 format
		X509EncodedKeySpec keyspec = new X509EncodedKeySpec(bytes);
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyfactory.generatePublic(keyspec);
		
		/* Read private key */
		path = Paths.get("./private.key");
		byte[] bytes2 = Files.readAllBytes(path);
		//Private key is stored in PKCS8 format
		PKCS8EncodedKeySpec keyspec2 = new PKCS8EncodedKeySpec(bytes2);
		KeyFactory keyfactory2 = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyfactory2.generatePrivate(keyspec2);
		
		/* Encrypt */
		System.out.println(".....MESSAGE RSA.....");
		byte[] messageRSA = "Hola mundooo!".getBytes();
        System.out.println("Plain text message: " + new String (messageRSA));
        System.out.println("Length of plain text message: " + messageRSA.length);
		System.out.println("......ENCRYPTION RSA.....");
        byte[] encryptedRSA = r.encrypt(messageRSA, publicKey);
        System.out.println("Encrypted: " + new String(encryptedRSA));
        String encryptedRSABase64 = Base64.getEncoder().encodeToString(encryptedRSA); 
        System.out.println("Encrypted (Base64): " + encryptedRSABase64);
        System.out.println("Length of encrypted text message:"  + encryptedRSA.length);
        
        /* Decrypt */
        System.out.println(".....DECRYPTION.....");
        byte[] decryptedRSA = r.decrypt(encryptedRSA, privateKey);
        System.out.println("Decrypted: " + new String(decryptedRSA));
        
        /* FIRMA Y VERIFICACION */
        
        /* Sign */
        System.out.println(".....MESSAGE TO SIGN.....");
		byte[] messageToSign = "Hola mundooo!".getBytes();
        System.out.println("Plain text message: " + new String (messageToSign));
        System.out.println("Length of plain text message: " + messageToSign.length);
        
		System.out.println("......SIGNING.....");
        byte[] messageSigned = r.sign(messageRSA, privateKey);
        System.out.println("Signed: " + new String(messageSigned));
        String signedBase64 = Base64.getEncoder().encodeToString(messageSigned); 
        System.out.println("Signed (Base64): " + signedBase64);
        System.out.println("Length of encrypted text message:"  + messageSigned.length);
        
        /* Verify */

        System.out.println(".....VERIFY.....");
        boolean verified = r.verify(messageToSign, messageSigned, publicKey);
        String status = String.format("Verification status: %s", verified ? "Verified" : "Not verified");
        System.out.println(status);
        
        /* Fail Verify */
        System.out.println(".....VERIFY FAIL.....");
        byte[] messageToSignFail = "Fail".getBytes();
        boolean verifiedFail = r.verify(messageToSignFail, messageSigned, publicKey);
        String statusFail = String.format("Verification status: %s", verifiedFail ? "Verified" : "Not verified");
        System.out.println(statusFail);
        
        
	}
}