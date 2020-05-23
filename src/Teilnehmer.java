import java.security.Key;
import java.security.PublicKey;

/**
 * Beschreiben Sie hier die Klasse Teilnehmer.
 * 
 * @author (Ihr Name) 
 * @version (eine Versionsnummer oder ein Datum)
 */
public class Teilnehmer
{
    private String nick = null;

    public EncryptionLib encInstance = null;

    public Key aesKey = null;
    public PublicKey pubKey = null;
    public boolean encryptionEstablished = false;

    public String identifier;

    /**
     * Konstruktor für Objekte der Klasse Teilnehmer
     */
    public Teilnehmer(String identifier)
    {
        this.identifier = identifier;
        this.encInstance = new EncryptionLib(null, null);
    }
    
    public String getNick()
    {
        return nick;
    }

    public void setNick(String nick) {
        this.nick = nick;
    }
}
