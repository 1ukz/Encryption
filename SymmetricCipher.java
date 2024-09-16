import javax.crypto.*;  
import java.security.InvalidKeyException;
import java.util.Arrays;  

public class SymmetricCipher {

	//clave de cifrado
    byte[] byteKey;

    SymmetricEncryption s;
    SymmetricEncryption d;
    
    //num de padding aniadido
    int paddingLength;

    // iv inicializado como constante
    static byte[] iv = new byte[] { 
        (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
        (byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, 
        (byte)51, (byte)52, (byte)53, (byte)54 
    };

    /* constructor method */
    public SymmetricCipher() {
        // vacio, ya que el iv ya esta iniciado estaticamente
    }

    /* method to add PKCS#5 padding */
    private byte[] addPadding(byte[] input) {
    	
        if (input.length % 16 != 0) {       	
	        // calcula del input, cuanto padding hara falta en el bloque necesario
	        paddingLength = 16 - (input.length % 16); 
	        // crea un nuevo array que contendra la longitud del input mas el padding, lo que ya hara que se pueda dividir perfectamente en bloques de 16
	        byte[] padded = new byte[input.length + paddingLength];
	        // copia los datos de un array al otro, es decir, los datos originales pero faltarian las posiciones donde va el padding por rellenar
	        System.arraycopy(input, 0, padded, 0, input.length);
	        // llena lo que queda del array con los datos copiados con el padding de PKCS#5
	        for (int i = 0; i < paddingLength; i++) {
	        	padded[input.length + i] = (byte) paddingLength;
	        }   
	        return padded;
        }else {
        	
        	return input;
        }
    }

    /* method to remove PKCS#5 padding */
    private byte[] removePadding(byte[] input) {
  		
    		//creamos un nuevo array con el tamanio de el input descifrado con el padding menos el num de padding que hay
    		byte[] decipheredText = new byte[input.length - this.paddingLength];
    		//copiamos el array sin el padding
    		decipheredText = Arrays.copyOfRange(input, 0, input.length - this.paddingLength);
    		
    		return decipheredText;
    }

    /* method to encrypt using AES/CBC/PKCS5 */
    public byte[] encryptCBC(byte[] input, byte[] byteKey) throws Exception {
        // crea una instancia de SymmetricEncryption con la clave dada
        SymmetricEncryption aes = new SymmetricEncryption(byteKey);
        
        // aniade padding al texto en claro 
        byte[] paddedInput = addPadding(input);

        // crea un array para almacenar el ciphertext final
        byte[] cipherText = new byte[paddedInput.length];

        // el primer bloque se XOR-ea con el IV
        byte[] block = iv;

        // cifra bloque por bloque 
        for (int i = 0; i < paddedInput.length; i += 16) {
            // extrae un bloque de 16 bytes del input con el padding 
            byte[] textToEncrypt = Arrays.copyOfRange(paddedInput, i, i + 16);
            // realiza el XOR entre el bloque de texto en claro y el bloque anterior (o IV)
            for (int j = 0; j < 16; j++) {
            	textToEncrypt[j] ^= block[j];
            }
            // cifra el bloque utilizando AES
            byte[] encryptedBlock = aes.encryptBlock(textToEncrypt);
            // copia el bloque cifrado al array final de ciphertext
            System.arraycopy(encryptedBlock, 0, cipherText, i, 16);
            // Actualizar el bloque anterior con el bloque cifrado actual para la próxima iteración
            block = encryptedBlock;
        }
        // devuelve el texto cifrado al completo
        return cipherText;
    }

    /* Method to decrypt using AES/CBC/PKCS5 */
    public byte[] decryptCBC(byte[] input, byte[] byteKey) throws Exception {
        // crea una instancia de SymmetricEncryption con la clave dada
        SymmetricEncryption aes = new SymmetricEncryption(byteKey);
        // crea un array para almacenar el texto descifrado final
        byte[] paddedDecipheredText = new byte[input.length];
    	int numBlocks = input.length / 16;
        byte[] lastBlock;
        
        // cifra bloque por bloque 
        for (int i = input.length - 16; i >= 0; i -= 16) {
            // extrae el bloque cifrado correspondiente de 16 bytes del input
            byte[] textToDecrypt = Arrays.copyOfRange(input, i, i + 16);
            // descifra el bloque utilizando AES
            byte[] decryptedBlock = aes.decryptBlock(textToDecrypt);
            
            if (i == 0) {
                // el ultimo bloque se XOR-ea con el IV
                lastBlock = this.iv;
            }else {
            	// sino, pilla el anterior bloque cifrado del input
            	lastBlock = Arrays.copyOfRange(input, i - 16, i);
            }
            // realiza el XOR entre el bloque de texto en claro y el bloque anterior (o IV)
            for (int j = 0; j < 16; j++) {
            	decryptedBlock[j] ^= lastBlock[j];
            }
            // copia el bloque cifrado al array final de ciphertext
            System.arraycopy(decryptedBlock, 0, paddedDecipheredText, i, 16);
        }
        // devuelve el texto cifrado al completo
        return removePadding(paddedDecipheredText);
    }
    	
    	
}
       

