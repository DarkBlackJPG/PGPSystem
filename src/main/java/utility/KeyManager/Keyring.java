package utility.KeyManager;

import ExceptionPackage.IncorrectKeyException;
import ExceptionPackage.KeyNotFoundException;
import org.bouncycastle.openpgp.*;
import utility.ExportedKeyData;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;

public interface Keyring {
    // Add and remove keys

    /**
     * Dodavanje tajnih kljuceva. Zamisljeno je da se radim preko
     * secret KEYRING-a. Po standardu - keyring se sastoji od Master kljuca + subkljucevi.
     * Ja sam napravio da radimo SAMO sa master kljucem. Zasto - pricali smo samo o jednim kljucem na predavanjima
     * i vezbama.
     * <p>
     * Dalje, prsledjuje se secret keyring i unutar metode mi pravimo novu listu u koju prvo
     * prekopiramo sve sto se nalazi u KOLEKCIJI keyring-ova i dodamo u listu novi kljuc.
     * Potom samo instanciramo novi SecretKeyCollection
     *
     * @param secretKey
     * @throws IOException
     * @throws PGPException
     */
    void addSecretKey(PGPSecretKeyRing secretKey) throws IOException, PGPException;

    /**
     * Pogledaj sta pise za dodavanje tajnih kljuceva, isto je sve, samo sto se u ovom slucaju
     * radi sa PublicKeyRing i publick keyring kolekcijom. Isti je "algoritam";
     *
     * @param publicKey
     * @throws IOException
     * @throws PGPException
     */
    void addPublicKey(PGPPublicKeyRing publicKey) throws IOException, PGPException;

    /**
     * U ovoj metodi treba uraditi proveru da li je kljuc sa dostavljenim KeyId postoji
     * ili ne! TODO
     * Pozivom ove metode prvo trazimo secret key i onda ga prosledjujemo istoimenoj metodi
     *
     * @param KeyId
     * @param password
     * @throws PGPException
     * @throws IncorrectKeyException
     */
    void removeSecretKey(long KeyId, String password) throws PGPException, IncorrectKeyException, KeyNotFoundException;

    /**
     * Ova metoda prvo radi ekstrakciju privatnog kljuca.
     * Razlika izmedju tajnog i privatnog kljuca je u tome sto je tajni kljuc sifrovan privatni kljuc.
     * Dakle, ekstrakcijom privatnog kljuca treba da dekriptujemo tajni kljuc. Tu onda proveravamo
     * da li je dobar password. Ako password nije dobar, baca se IncorrectKeyException!
     * <p>
     * Ako je kljuc dobar, onda ulazimo u narednu metodu koja se zove removeGivenSecretKeyFromCollection.
     * Za vise detalja o ovoj metodi, pogledati sam KeyringManager.java kako je ova metoda privatna.
     *
     * @param keyRing
     * @param password
     * @throws IncorrectKeyException
     */
    void removeSecretKey(PGPSecretKeyRing keyRing, String password) throws IncorrectKeyException;

    /**
     * U ovoj metodi treba uraditi proveru da li je kljuc sa dostavljenim KeyId postoji
     * ili ne! TODO
     * Pozivom ove metode prvo trazimo public key i onda ga prosledjujemo istoimenoj metodi
     *
     * @param KeyId
     * @throws PGPException
     * @throws IOException
     */
    void removePublicKey(long KeyId) throws PGPException, IOException;

    /**
     * TODO Tu treba provera za postojanje kljuca.
     * Ako kljuc postoji trebalo bi da se pozove removeGivenPublicKeyFromCollection. pogledati .java fajl.
     * Ovo je privatna metoda;
     *
     * @param keyRing
     * @throws IOException
     * @throws PGPException
     */
    void removePublicKey(PGPPublicKeyRing keyRing) throws IOException, PGPException;

    // Key generation

    /**
     * Treba dostaviti PGP pair od RSA utility klase. Ima primer kako se generise par kljuceva u testovima,
     * to je sve sto treba da se zna, ne znam da li sam napisao komentae tamo.
     * <p>
     * Ova metoda prvo pravi flegove kao sto su za sta kljuc sluzi, koji su simetricni algoritmi koje perferiramo,
     * hash alg, postavlja se datum isteka kljuca - default-no 1 godina. To je hash flags, onda posle toga
     * idu non hash flagovi koji se vezuju za subkeys (koje ne koristimo tkd su tehnicki suvisni)
     * <p>
     * Posle toga se pravi Keyring generator koji ima zadatak da sve to upakuje u keyring-ove.
     * <p>
     * Svi podaci mogu da se izvuku iz PGPSecretKeyring jer secret key sadrzi i javni kljuc koji sadrzi
     * sve info o javnom kljuc.
     * <p>
     * Posle iz generatora generisemo keyringove (sa svim tim upakovanim flagovima/info)
     * <p>
     * Kada generisemo - dodajemo keyringove u public key i secret key kolekcije.
     * <p>
     * Kada se to uradi, poziva se saveKeys koji samo pravi dva fajla i cuva u projektu
     * <p>
     * TODO Ekstrahovati nazive fajlova kao final staitc
     * @param masterKey
     * @param subKey
     * @param username
     * @param email
     * @param password
     * @throws PGPException
     * @throws IOException
     */
    void makeKeyPairs(PGPKeyPair masterKey, PGPKeyPair subKey, String username, String email, String password) throws PGPException, IOException;

    // Helper methods

    /**
     * Kao sto ime kaze, helper funkcija koja cuva kljuceve na preodredjeno mesto sa nepredodredjenim nazivima fajla.
     * Ova metoda konkretno poziva istoimenu metodu kako se ova metoda poziva kada zelimo da sacuvamo javni i tajni
     * keyting collection sto se interno nalazi u KeyringManager-u.
     * <p>
     * TODO: Provera da li su null
     *
     * @param publicKeyFileLocation
     * @param secretKeyFileLocation
     * @throws IOException
     */
    void saveKeys(String publicKeyFileLocation, String secretKeyFileLocation) throws IOException;

    /**
     * U ovoj metodi se konkretno samo prave ourput stream-ovi, file streamovi.
     * Potom samo pisanje fajla delegiramo writeKeyToFIle funkciji koja obavlja sam zadatak pisanja.
     * Metoda je privatna tkd pogledaj .java fajl za vise info
     *
     * @param publicKeyRings
     * @param secretKeyRings
     * @param publicKeyFileLocation
     * @param secretKeyFileLocation
     * @throws IOException
     */
    void saveKeys(PGPPublicKeyRingCollection publicKeyRings, PGPSecretKeyRingCollection secretKeyRings, String publicKeyFileLocation, String secretKeyFileLocation) throws IOException;

    /**
     * Ovu metodu treba koristiti iskljucivo kada zelimo da ispisemo celu kolekciju koja se nalazi u nasem
     * menadzeru,
     * TODO: Provera null za kolekcije
     *
     * @return
     */
    ArrayList<ExportedKeyData> generatePublicKeyList();

    /**
     * Ova metoda ima zadatak da formatira kolekcije za jednostavnije baratanje kljucevima.
     * Vraca listu svih kljuceva na malo cudan nacin.
     * <p>
     * Naime, pretpostavka je da se svaki tajni kljuc (pod ovo mislim keyID tajnog kljuca) nalazi u
     * public key kolekciji, ali javni kljuc ne mora da se nalazi u private key kolekciji.
     * <p>
     * U svakom slucaju -> prolazimo kroz sve javne kljuceve, ubacujemo u novi niz tako sto
     * uzimamo javni kljuc i prosledjujemo ga metodi extractDataFromKey (pogledaj .java za vise info)
     * i on nam formatira informacije tako sto napravi objekat ExportedKeyData koji ima neke atribute od znacaja
     * za ispis.
     * <p>
     * Potom, prolazimo kroz sve tajne kljuceve, ako naidjemo na keyID koji se nalazi u listi, obavezno
     * stavljamo flag da je master, iliti (mozes da shvatis zbog ovog "frameworka") za taj KeyID posedujemo i privatni
     * kljuc sto znaci da mozemo da potpisujemo sa njim.
     *
     * @param publicKeyRings
     * @param secretKeyRings
     * @return
     */
    ArrayList<ExportedKeyData> generatePublicKeyList(PGPPublicKeyRingCollection publicKeyRings, PGPSecretKeyRingCollection secretKeyRings);

    // -------------------------
    // --- Sledece tri metode --
    // --- Nisu testirane ------
    // -------------------------

    /**
     * Obavezno treba proveriti van ove metode da li je pronadjen kljuc ili ne
     * Nista
     *
     * @param keyId
     * @return
     * @throws PGPException
     */
    PGPSecretKey getSecretKeyById(long keyId) throws PGPException;

    /**
     * Obavezno van metode proveriti da li je uspesno dekriptovano - dobija se null ako je neuspesno!
     * Dekripcija je efektivno ista kao kod brisanja
     *
     * @param secretKey
     * @param password
     * @return
     */
    PGPPrivateKey decryptSecretKey(PGPSecretKey secretKey, String password);

    /**
     * Isto kao decryptSecret key, samo sto nas ne zanima private key nego
     * samo da li se passwordi poklapaju
     *
     * @param secretKey
     * @param password
     * @return
     */
    boolean checkPasswordMatch(PGPSecretKey secretKey, String password);

    // Imports and exports

    /**
     * Ova metoda je krindz hehehhehehe
     * <p>
     * Drzi na umu ono - nemamo master key i sub kljuceve vec sve radimo sa jednim kljucem te keyring postaje nas kljuc!
     * <p>
     * TODO: Da li kljuc postoji?
     * <p>
     * Prvo dohvatamo public key iz kolekcije (pretpostavka je da SVI keyID tamo postoje)
     * <p>
     * Onda dolazi onaj krindz deo - Pravimo KeyRing tako sto pravimo arraylist sa samo jednim javnim
     * kljucem i ubacujemo u konstruktor keyring-a i to prosledjujemo nadalje u istoimenu metodu
     *
     * @param KeyId
     * @param os
     * @throws PGPException
     * @throws IOException
     */
    void exportPublicKey(long KeyId, OutputStream os) throws PGPException, IOException, KeyNotFoundException;

    /**
     * TODO Isto fale neke provere sig
     * <p>
     * Pozivamo write Key to file metodu, naci u .java
     *
     * @param pgpPublicKey
     * @param os
     * @throws PGPException
     * @throws IOException
     */
    void exportPublicKey(PGPPublicKeyRing pgpPublicKey, OutputStream os) throws PGPException, IOException;

    /**
     * Sejm shit kao i za public
     *
     * @param KeyID
     * @param outputStream
     * @throws PGPException
     * @throws IOException
     * @throws KeyNotFoundException
     */
    void exportSecretKey(long KeyID, OutputStream outputStream) throws PGPException, IOException, KeyNotFoundException;

    /**
     * Sejm shit kao i za public
     *
     * @param key
     * @param outputStream
     * @throws PGPException
     * @throws IOException
     * @throws KeyNotFoundException
     */
    void exportSecretKey(PGPSecretKeyRing key, OutputStream outputStream) throws IOException;

    /**
     * Ovu metodu ne treba koristiti, konsultovati importSecretKeyring metodu
     *
     * @param secretKey
     * @throws IOException
     * @throws PGPException
     * @Depricated
     */
    void addSecretKey(InputStream secretKey) throws IOException, PGPException;

    /**
     * Ovu metodu ne treba koristiti, konsultovati importPublicKeyring metodu
     *
     * @param publicKey
     * @throws IOException
     * @throws PGPException
     * @Depricated
     */
    void addPublicKey(InputStream publicKey) throws IOException, PGPException;

    void importSecretKeyring(InputStream is) throws IOException, PGPException;

    void importPublicKeyring(InputStream is) throws IOException, PGPException;
}
