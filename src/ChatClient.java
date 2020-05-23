import javax.crypto.KeyGenerator;
import javax.swing.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Scanner;

/**
 * Klasse fuer einen EchoClient
 * @author Henning Ainödhofer
 * @version 21.3.2015
 */

public class ChatClient extends Client 
{
    private KeyPair KP;
    private EncryptionLib EL;

    private Key aesKey;
    private PublicKey serverPubkey;

    private volatile boolean encryptionEstablished = false;

    public ChatClient(String ip, int p) throws Exception {
        super(ip, p);
        System.out.println("[*] Verbindung wird hergestellt...");
        
        while(!this.isConnected()) {}

        System.out.println("[OK] Verbindung hergestellt!");

        KP = EncryptionLib.generateRSAKeypair();
        EL = new EncryptionLib(KP.getPublic(), KP.getPrivate());

        sendPublicKey();

        while (!encryptionEstablished) {
            Thread.onSpinWait();
        }

        Scanner sc = new Scanner(System.in);
        System.out.print("Name: ");
        String name = sc.nextLine();

        System.out.print("Passwort: ");
        // Das ist eine absolut schreckliche Methode Passwörter zu speichern.
        // SHA512 ohne Salt ist unsicher. Am besten wird das hier ersetzt durch bcrypt or PBKDF2.
        // Ich würde es besser machen, aber es ist 23 Uhr und ich bin müde.
        // Außerdem ist Java schrecklich wenn es um externe Abhängigkeiten geht.
        String password = EncryptionLib.get_SHA_512(sc.nextLine(), "");
        
        this.sendEncrypted("LOGIN " + name + " : " + password , aesKey, EL);
        
        while (true) {
            String msg = sc.nextLine();
            if(!gibBefehlsbereich(msg).equals("ANM")) {
                this.sendEncrypted("MSG " + msg, aesKey, EL);
            }
        }
    }

    private void sendPublicKey() {
        System.out.println("[*] Verschlüsselte Kommunikation wird aufgebaut...");

        System.out.println("[*] Public Key wird gesendet...");
        this.send("ENC START " + new String(Base64.getEncoder().encode(KP.getPublic().getEncoded())));
    }

    /**
     * Diese Methode der Client-Klasse wird hiermit ueberschrieben.
     * Der Client gibt die erhaltende Meldung, auf dem Textfeld aus.
     */
    public void processMessage(String message) throws Exception {
        if(gibBefehlsbereich(message).equals("ENCRYPTED")) { // If message is encrypted, decrypt with the known AES key first
            try {
                if(gibTextbereich(message).split(" ").length != 2) return;

                String ciphertext = gibTextbereich(message).split(" ")[0];
                String hmac = gibTextbereich(message).split(" ")[1];

                String computedHMAC = EncryptionLib.calculateHMAC(ciphertext, Base64.getEncoder().encodeToString(aesKey.getEncoded()) + Math.floor((Instant.now().getEpochSecond() - 1) / 30));

                if(!computedHMAC.equals(hmac)) {
                    System.out.println("[ERR] HMAC passt nicht!\n[ERR] Dies wurde entweder durch eine schlechte Verbindung oder einen Angriff verursacht!");
                    return;
                }

                message = EL.AESdecrypt(gibTextbereich(message).split(" ")[0], aesKey);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        switch(gibBefehlsbereich(message))
        {
            case "ENC":
            {
                if(gibTextbereich(message).length() >= 3 && gibTextbereich(message).substring(0, 3).equals("KEY")) {

                    String pubKey = gibTextbereich(message).substring(4);
                    serverPubkey = EncryptionLib.PublicKeyFromString(EncryptionLib.stripString(pubKey));
                    System.out.println("[OK] RSA Schlüssel vom Server erhalten: " + pubKey);

                    KeyGenerator keygen = KeyGenerator.getInstance("AES");
                    keygen.init(128);
                    aesKey = keygen.generateKey();

                    System.out.println("[*] AES Schlüssel: " + new String(Base64.getEncoder().encode(aesKey.getEncoded())));

                    this.send("ENC AES " + EL.rawRSAEncrypt(new String(Base64.getEncoder().encode(aesKey.getEncoded())), serverPubkey));

                    System.out.println("[OK] AES Schlüssel verschlüsselt übertragen!");
                } else if (gibTextbereich(message).equals("PING")) {
                    this.sendEncrypted("ENC PONG", aesKey, EL);
                    System.out.println("[OK] Verschlüsselter Ping gesendet.");
                } else if (gibTextbereich(message).equals("OK")) {
                    System.out.println("[OK] Verschlüsselte Ping-Antwort erhalten!");
                    System.out.println("[DONE] Verschlüsselter Kanal geöffnet!");
                    encryptionEstablished = true;
                }
                break;
            }
            case "MSG":
            {
                System.out.println(gibTextbereich(message));
                break;
            }
            case "EXT":
            {
                this.close();
                break;
            }
            default:
            {
                System.out.println(message);
            }
        }
    }

    /**
     * Diese Methode gibt den Befehl zurück die die message beinhaltet
     * 
     * @param message
     * 
     * @return Befehl
     */
    private String gibBefehlsbereich(String message)
    {
        return message.split(" ")[0];
    }

    /**
     * Diese Methode gibt den Text zurück die die message beinhaltet !! wichtig !! Alle Befehle müssen 4 Zeichen enthalten!
     * 
     * @param message
     * @param stelle
     * 
     * @return Text
     */
    private String gibTextbereich(String message)
    {
        String[] split = message.split(" ");

        return message.substring(split[0].length() + 1);
    }

    public static void main(String[] args) throws Exception {
        ChatClient es = new ChatClient("127.0.0.1", 2000);
    }
}
