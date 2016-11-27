import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RSAEncryption {

    private BigInteger n;
    private BigInteger phi;
    //Static public key for encrypting
    private final BigInteger publicKey = new BigInteger("6553765537");
    //Dynamic private key, not set until needed.
    public BigInteger privateKey;

    public static void main(String[] args) throws UnsupportedEncodingException, IOException, FileNotFoundException, ClassNotFoundException {

        //Create a new RSA object to calculate with.
        RSAEncryption rsae = new RSAEncryption();
        //If the length is one, then we're decrypting. If it is two then we're encrypting.
        switch (args.length) {
            case 1:
                if (args[0].equalsIgnoreCase("decrypt")) {
                    rsae.decrypt();
                } else {
                    System.out.println("If decrypting, please type decrypt");
                }
                break;
            case 2:
                if (args[1].equalsIgnoreCase("encrypt")) {
                    rsae.setupEncryption();
                    rsae.encrypt(args[0].getBytes());
                } else {
                    System.out.println("If encrypting, please type <String> encrypt");
                }
                break;
            //User put in zero or three or more arguements.
            default:
                System.out.println("Usage: java RSAEncryption <String> Encrypt \nor: java RSAEncryption Decrypt");

        }
    }

    /*
     Purpose: Encrypt a String the user has put in. With the variables already set up, it only needs to perform:
     Character(as byte)^publicKey mod n and that will encrypt the file for the user. The file is additionally written to file
     encrypted so it can be decrypted later.
     */
    private void encrypt(byte[] messageBytes) throws FileNotFoundException, UnsupportedEncodingException, IOException {
        try (PrintWriter writer = new PrintWriter("encryptedFile.txt", "UTF-8")) {
            for (int i = 0; i < messageBytes.length; i++) {
                writer.println(BigInteger.valueOf(messageBytes[i]).modPow(publicKey, n) + "\n");
            }
            System.out.println("Encryption is done!");
        }
    }
    /*
        This undoes the encryption done. n (the previous product of p and q) and a private key are retreived from a file. When my application encrypts
        a file it creates a new private key every time assuming it is sent to a new person. It also doesn't have a mechanism to store private keys while
    having the capabilities of knowing who is sending the messages. This is why for now n and the private key are retreived from a file for decryption. 
     */

    private void decrypt() {
        //get n and private key.
        findKey();
        //read the encrypted file.
        try (BufferedReader br = new BufferedReader(new FileReader("encryptedFile.txt"))) {
            String line = br.readLine();
            while (line != null) {
                if (!line.equals("")) {
                    //Print the byte value of a decrypted value.
                    System.out.print((char) new BigInteger(line).modPow(privateKey, n).byteValue());
                }
                line = br.readLine();
            }
        } catch (FileNotFoundException ex) {
            System.out.println("Please encrypt a file before attempting to decrypt a file.");
        } catch (IOException ex) {
            System.out.println("There was an error reading the file");
        }
    }

    //Sets up the variables to create a private key for encrypting. 
    private void setupEncryption() {
        // Creata 1024 bit number for added security.
        BigInteger p = new BigInteger(1024, 110, new Random()).nextProbablePrime();
        //Grab the new prime number from p
        BigInteger q = p.nextProbablePrime();
        //Do a probability check to make sure it's prime. The check does 1 - 0.5^certainty. 1-05^110 = 1 which should mean it's always prime.
        if(q.isProbablePrime(110)){
        //Grab n by multiplying p and q.
        n = p.multiply(q);
        //PHI is (p-1)*(q-1)
        phi = (p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)));
        //Make the private key.
        setupDecryption();
        }else{
            //If the certainty check fails. Run the method again until it passes.
            setupEncryption();
        }
    }

    //Creates the private key. This is seperate because there is a lot of extra code I've created just for one variable.
    private void setupDecryption() {
        try {
            //The inverse of the public key should be the private key. a way to get this is using euclid's extended algorithm. However,
            //as I'm using big numbers and modInverse is built into the BigInteger class, I decided to use it instead.
            privateKey = publicKey.modInverse(phi);
        } catch (ArithmeticException ae) {
            //If for some reason something goes wrong with the mod inverse then recreate everything again.
            setupEncryption();
        }
        //Write the private key and n to file.
        try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("knownPrivateKeys.txt")))) {
            out.println("Private Key:");
            out.println(privateKey);
            out.println("n:");
            out.println(n);
        } catch (IOException e) {
            System.out.println("Something went wrong when writing to file.");
        }
    }

    //Pulls the private key and n from a file.
    private void findKey() {
        
        int counter = 0;
        try (BufferedReader br = new BufferedReader(new FileReader("knownPrivateKeys.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                
                if (counter == 1) {
                    privateKey = new BigInteger(line);

                } else if (counter == 3) {
                    n = new BigInteger(line);
                }
                counter++;
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(RSAEncryption.class.getName()).log(Level.SEVERE, "File is not in current directory.", ex);
        } catch (IOException ex) {
            Logger.getLogger(RSAEncryption.class.getName()).log(Level.SEVERE, "Error writing to file.", ex);
        }
    }

}

