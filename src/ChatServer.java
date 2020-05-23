import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.lang.constant.Constable;
import java.nio.charset.StandardCharsets;
import java.net.*;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.text.SimpleDateFormat;

/**
 * Klasse fuer einen ChatServer
 * @author Henning Ainödhofer
 * @version 21.03.2015
 */

public class ChatServer extends Server {
    private EncryptionLib EL;
    private PublicKey pubkey;
    private PrivateKey privkey;

    List <Teilnehmer> tn;
    List <Account> accounts;

    public ChatServer(int p) throws Exception {
        super(p);
        tn = new List<Teilnehmer>();
        accounts = new List<Account>();

        if(new File("accounts.txt").isFile()) {
            System.out.print("Accountliste: ");

            // Accounts sind in accounts.txt gespeichert.
            try(BufferedReader br = new BufferedReader(new FileReader("accounts.txt"))) {
                StringBuilder sb = new StringBuilder();
                String line = br.readLine();

                while (line != null) {
                    sb.append(line);

                    String username = line.split(" : ")[0];
                    String password = line.split(" : ")[1];
                    accounts.append(new Account(username, password));

                    System.out.print(username + " ");

                    line = br.readLine();
                }
                String everything = sb.toString();
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("[WARN] Accounts.txt konnte nicht gelesen werden!");
            }
        } else {
            new File("accounts.txt").createNewFile();
            System.out.println("[*] Accounts.txt wurde erstellt.");
        }

        KeyPair kp = EncryptionLib.generateRSAKeypair();
        this.pubkey = kp.getPublic();
        this.privkey = kp.getPrivate();

        EL = new EncryptionLib(this.pubkey, this.privkey);
    }

    /**
     * Diese Methode der Server-Klasse wird hiermit ueberschrieben.
     * Der angemeldete Client bekommt die Meldung, dass er angenommen wurde.
     * @param pClientIP
     * @param pClientPort
     */
    public void processNewConnection(String pClientIP, int pClientPort) {

        tn.append(new Teilnehmer(EncryptionLib.get_SHA_512(pClientIP + pClientPort, "")));

        this.send(pClientIP, pClientPort, "CON complete");
    }

    private Teilnehmer findeTeilnehmerMitIdentifier(String identifier) {
        synchronized (tn) {
            tn.toFirst();
            while(tn.hasAccess()) {
                if(tn.getContent().identifier.equals(identifier)) {
                    return tn.getContent();
                }
                tn.next();
            }
            return null;
        }
    }

    private Account findeAccount(String username) {
        synchronized (accounts) {
            accounts.toFirst();
            while(accounts.hasAccess()) {
                if(accounts.getContent().username.equals(username)) {
                    return accounts.getContent();
                }
                accounts.next();
            }
            return null;
        }
    }

    private void createNewAccount(String username, String hash) throws Exception {
        synchronized (accounts) {
            accounts.append(new Account(username, hash));

            FileWriter fw = new FileWriter("accounts.txt", true);
            BufferedWriter bw = new BufferedWriter(fw);
            bw.write(String.format("%s : %s", username, hash));
            bw.newLine();
            bw.close();
        }
    }

    /**
     * Diese Methode der Server-Klasse wird hiermit ueberschrieben.
     * Der angemeldete Client bekommt die gesendete Meldung zurueckgeschickt.
     * @param pClientIP
     * @param pClientPort
     * @param pMessage
     */
    public void processMessage(String pClientIP, int pClientPort, String pMessage) throws Exception {
        Teilnehmer tn = findeTeilnehmerMitIdentifier(EncryptionLib.get_SHA_512(pClientIP + pClientPort, ""));

        if(pMessage.substring(0, 9).equals("ENCRYPTED")) { // If message is encrypted, decrypt with the known AES key first
            System.out.println("Encrypted message: " + gibTextbereich(pMessage));
            try {
                if(gibTextbereich(pMessage).split(" ").length != 2) return;

                String ciphertext = gibTextbereich(pMessage).split(" ")[0];
                String hmac = gibTextbereich(pMessage).split(" ")[1];

                String computedHMAC = EncryptionLib.calculateHMAC(ciphertext, Base64.getEncoder().encodeToString(tn.aesKey.getEncoded()) + Math.floor((Instant.now().getEpochSecond() - 1) / 30));

                if(!computedHMAC.equals(hmac)) {
                    System.out.println("HMAC not matching! Skipping message.");
                    return;
                }

                pMessage = tn.encInstance.AESdecrypt(gibTextbereich(pMessage).split(" ")[0], tn.aesKey);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        System.out.println("From " + tn.identifier + ": " + pMessage);

        String usernamePattern = "(\\s)(\\s\\s)(\\s\\s\\s)";
        switch (gibBefehlsbereich(pMessage)) {
            case "ENC":
                if(gibTextbereich(pMessage).length() >= 5 && gibTextbereich(pMessage).substring(0, 5).equals("START")) {
                    String pubKey = pMessage.substring(10);
                    tn.pubKey = EncryptionLib.PublicKeyFromString(EncryptionLib.stripString(pubKey));
                    System.out.println("Client with pub key joined: " + EncryptionLib.stripString(pubKey));

                    this.send(pClientIP, pClientPort, "ENC KEY " + new String(Base64.getEncoder().encode(pubkey.getEncoded())));
                } else if(gibTextbereich(pMessage).length() >= 3 && gibTextbereich(pMessage).substring(0, 3).equals("AES")) {
                    String aesKey = EL.RSAdecryptMessage(gibTextbereich(pMessage).substring(4));

                    tn.aesKey = EL.AESKeyFromString(aesKey);

                    System.out.println("Got AES-Key: " + new String(Base64.getEncoder().encode(tn.aesKey.getEncoded())));

                    this.sendEncrypted(pClientIP, pClientPort, "ENC PING", tn.aesKey, EL);
                } else if(gibTextbereich(pMessage).equals("PONG")) {
                    tn.encryptionEstablished = true;
                    System.out.println(tn.identifier + " has finished authentication!");

                    this.sendEncrypted(pClientIP, pClientPort, "ENC OK", tn.aesKey, EL);
                }
                break;
            case "MSG":
                {
                    Date date = new Date();
                    SimpleDateFormat sdf = new SimpleDateFormat("h:mm");
                    String formattedDate = sdf.format(date);

                    if(tn.getNick() == null) {
                        this.sendEncrypted(pClientIP, pClientPort, String.format("MSG (%s) Server -> Du: Du hast noch keinen Nicknamen. Logge dich zuerst ein.", formattedDate), tn.aesKey, tn.encInstance);
                        break;
                    }

                    this.sendToAll(String.format("MSG (%s) %s: %s", formattedDate, tn.getNick(), pMessage));
                    break;
                }
            case "ABM":
                {
                    synchronized(this) {
                        processClosingConnection(pClientIP, pClientPort);
                    }
                }
            case "LOGIN":
                {
                    String username = gibTextbereich(pMessage).split(" : ")[0];
                    String passwordHash = gibTextbereich(pMessage).split(" : ")[1];

                    if (username.isEmpty() || username.matches(usernamePattern)) {
                        this.send(pClientIP, pClientPort, "ERR02 Leerer Nutzername");
                        break;
                    }

                    Account ac = findeAccount(username);

                    Date date = new Date();
                    SimpleDateFormat sdf = new SimpleDateFormat("h:mm");
                    String formattedDate = sdf.format(date);

                    if(ac == null) {
                        createNewAccount(username, passwordHash);
                        tn.setNick(username);
                    } else if(ac.username.equals(username) && ac.password.equals(passwordHash)) {
                        tn.setNick(username);
                    } else {
                        this.sendEncrypted(pClientIP, pClientPort, "MSG (" + formattedDate + ") Server -> Du: Ungültiges Passwort. Versuche es erneut.", tn.aesKey, tn.encInstance);
                        break;
                    }

                    this.sendToAll("MSG (" + formattedDate + ") Willkommen im Chatraum, " + username + "!");
                    break;
                }
            default:
                {
                    this.send(pClientIP, pClientPort, "ERR01 Befehl nicht bekannt");
                    break;
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
    private String gibBefehlsbereich(String message) {
        return message.split(" ")[0];
    }

    /**
     * Diese Methode gibt den Text zurück die die message beinhaltet.
     * Repariert und mit vernünftigen Code ersetzt, der längere Kommandos unterstützt.
     * 
     * @param message
     * 
     * @return Text
     */
    private String gibTextbereich(String message) {
        String[] split = message.split(" ");

        return message.substring(split[0].length() + 1);
    }

    /**
     * Diese Methode der Server-Klasse wird hiermit ueberschrieben.
     * Die Verbindung wird beendet und aus der Liste der Clients gestrichen.
     * @param pClientIP
     * @param pClientPort
     */
    public void processClosingConnection(String pClientIP, int pClientPort) {
        //this.sendToAll("MSG" + pClientIP + " hat den Chat verlassen."); //Abschiedsnachricht an alle anderen
        this.closeConnection(pClientIP, pClientPort);
    }

    public void sendToAll(String pMessage) throws Exception {
        synchronized(messageHandlers)
        {
            synchronized (tn) {
                messageHandlers.toFirst();
                while (messageHandlers.hasAccess())
                {
                    ClientMessageHandler cmh = messageHandlers.getContent();
                    Teilnehmer tn = findeTeilnehmerMitIdentifier(EncryptionLib.get_SHA_512(cmh.getClientIP() + cmh.getClientPort(), ""));

                    if(tn.encryptionEstablished) {
                        messageHandlers.getContent().sendEncrypted(pMessage, tn.aesKey, tn.encInstance);
                    }

                    messageHandlers.next();
                }
            }

        }
    }

    /**
     * Main Methode zum starten des Servers
     */
    public static void main(String[] args) throws Exception {
        ChatServer es = new ChatServer(2000);
    }
}