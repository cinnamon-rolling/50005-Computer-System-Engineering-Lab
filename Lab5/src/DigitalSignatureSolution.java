import java.util.Base64;
import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.*;


public class DigitalSignatureSolution {

    public static void main(String[] args) throws Exception {
//Read the text file and save to String data
        String fileName = "src/shorttext.txt";
        String data = "";
        String line;
        BufferedReader bufferedReader = new BufferedReader( new FileReader(fileName));
        while((line= bufferedReader.readLine())!=null){
            data = data +"\n" + line;
        }
        System.out.println("Original content: "+ data);
        System.out.println((data.length()));

//TODO: generate a RSA keypair, initialize as 1024 bits, get public key and private key from this keypair.
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(data.getBytes());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGen.generateKeyPair();
        Key publicKey = keyPair.getPublic();
        Key privateKey = keyPair.getPrivate();

//TODO: Calculate message digest, using MD5 hash function
        byte[] digest = md.digest();

//TODO: print the length of output digest byte[], compare the length of file smallSize.txt and largeSize.txt
        System.out.println(digest.length);
           
//TODO: Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as encrypt mode, use PRIVATE key.
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);

//TODO: encrypt digest message
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encryptedBytes = cipher.doFinal(digest);
        System.out.println("size of encryptedBytes: " + encryptedBytes.length);

//TODO: print the encrypted message (in base64format String using Base64) 
        String dataEncrypted = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println(dataEncrypted);

//TODO: Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as decrypt mode, use PUBLIC key.           
        Cipher desCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        desCipher.init(Cipher.DECRYPT_MODE, publicKey);

//TODO: decrypt message
        byte[] decryptedBytesArray = desCipher.doFinal(encryptedBytes);

//TODO: print the decrypted message (in base64format String using Base64), compare with origin digest 
        String desDataEncrypted = Base64.getEncoder().encodeToString(decryptedBytesArray);
        System.out.println(desDataEncrypted.length()); // 24
        System.out.println(decryptedBytesArray.length); // 16


    }

}