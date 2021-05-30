package sample;

import ExceptionPackage.IncorrectKeyException;
import ExceptionPackage.KeyNotFoundException;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.util.Callback;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPSecretKey;
import utility.KeyManager.KeyringManager;
import utility.RSA;
import utility.helper.EncryptionWrapper;
import utility.KeyManager.ExportedKeyData;
import utility.helper.PasswordDialog;

import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Glavni kontroler za FX view
 */

// ----------|
// PRIVREMENO|
// ----------|


public class Controller {
   /************************ ENCRYPTION *****************************/
    @FXML
    private Button browseFileChooserTriggerButton;
    @FXML
    private TextField browseFileLocationTextField;
    @FXML
    private CheckBox useEncryptionCheckBox;
    @FXML
    private ChoiceBox encryptionAlgorithmsChoiceBox; // Ne trebaju kljucevi
    @FXML
    private CheckBox signCheckBox;
    @FXML
    private ChoiceBox signChoiceBox;
    @FXML
    private CheckBox compressionCheckBox;
    @FXML
    private CheckBox base64ConversionCheckBox;
    @FXML
    private Button sendButton;
    @FXML
    private TableView publicKeyEncryptionChoiceTableView;
    /************************ DECRYPTION *****************************/
    @FXML
    private Button browseDecryptionFileChooserTriggerButton;
    @FXML
    private TextField browseDecryptionFileLocationTextField;
    @FXML
    private Button decryptAndVerifyButton;
    @FXML
    private TextArea displayDecriptionAndVerificationOutputTextField;
    @FXML
    private Button saveDecryptionFileLocationButton;
    @FXML
    private TextField decryptionFileLocationTextField;
    @FXML
    private Button saveDecryptionFileButton;
    /************************ EXPORT KEYS *******************************/
    @FXML
    private Button browseExportKeysFileButton;
    @FXML
    private TextField exportFileLocationTextField;
    @FXML
    private Button executeExportKeyButton;
    @FXML
    private ComboBox exportKeyChoiceCombobox;
    /*********************** IMPORT KEYS ****************************/
    /**** PRIVATE ***/
    @FXML
    private Button browseImportSecretKeyButton;
    @FXML
    private TextField pathToImportKeyFileTextField;
    @FXML
    private Button executeImportSecretKeyButton;
    /**** PUBLIC ***/
    @FXML
    private Button browseImportPublicKeyButton;
    @FXML
    private Button executeImportPublicKeyButton;
    @FXML
    private TextField publicKeyFIleLocationTextField;
    /************************ CERTIFICATES *******************************/
    @FXML
    private TableView certificateTableTableView;
    /************************ GENRATE NEW KEYPAIR *******************************/
    @FXML
    private TextField newKeyPairName;
    @FXML
    private TextField newKeyPairEmail;
    @FXML
    private PasswordField newKeyPairPassword;
    @FXML
    private ComboBox newKeyPairAlgorithm; // ne trebaju kljucevi
    @FXML
    private Button generateNewKeyPairButton;



    private List<String> symmetricAlgorithms = new ArrayList<>();
    private List<String> asymmetricAlgorithms = new ArrayList<>();
    private ObservableList<ExportedKeyData> allKeys = FXCollections.observableArrayList();

    KeyringManager keyManager;
    

    // Sluzi za parsiranje stringa prilikom odabira iz choice box-a za novi tajni kljuc
    private HashMap<String, RSA.KeySizes> rsaKeySizesHashMap = new HashMap<>();

    private HashMap<String, Integer> symmetricAlgorithmsHashMap = new HashMap<>();


    // Inicijalizacija neophodnih struktura podataka za ispis u FX komponente
    public Controller() {
        String rsa1024 = "RSA 1024";
        String rsa2048 = "RSA 2048";
        String rsa4096 = "RSA 4096";

        String tripleDES = "Triple DES";
        String idea = "IDEA";

        symmetricAlgorithms.add(tripleDES);
        symmetricAlgorithms.add(idea);

        symmetricAlgorithmsHashMap.put(tripleDES, SymmetricKeyAlgorithmTags.TRIPLE_DES);
        symmetricAlgorithmsHashMap.put(tripleDES, SymmetricKeyAlgorithmTags.IDEA);

        asymmetricAlgorithms.add(rsa1024);
        asymmetricAlgorithms.add(rsa2048);
        asymmetricAlgorithms.add(rsa4096);

        rsaKeySizesHashMap.put(rsa1024, RSA.KeySizes.RSA1024);
        rsaKeySizesHashMap.put(rsa2048, RSA.KeySizes.RSA2048);
        rsaKeySizesHashMap.put(rsa4096, RSA.KeySizes.RSA4096);

        try {
            keyManager = new KeyringManager();
            Main.keyManagerReference = keyManager;
        } catch (Exception e) {
            showErrorDialog("Error encountered",
                    "Error trying to open keyring files",
                    e.getMessage() + "\n Try opening the application again.");
        }


    }

    /**
     * Ovo je inicijalizovanje pogled.
     * Izvrsava se pre svaceg, automatski se poziva.
     */
    @FXML
    void initialize() {
        // Ubacujemo algoritme koje nudomo, algoritmi su definisani gore u inicijalizacionom bloku
        encryptionAlgorithmsChoiceBox.setItems(FXCollections.observableList(symmetricAlgorithms));
        newKeyPairAlgorithm.setItems(FXCollections.observableList(asymmetricAlgorithms));

        // Koristimo observable list da automatski azuriramo podatke kada se desi neka promena
        // [INTEGRACIJA] Testirati ovaj Listener -- Trebalo bi da radi
        // Ovo je implementacija Observer patterna, tu registrujemo sve koji posmatraju promenu i azuriramo podatke
        allKeys.addListener((ListChangeListener<? super ExportedKeyData>) change -> {
            certificateTableTableView.getItems().clear();
            publicKeyEncryptionChoiceTableView.getItems().clear();
            signChoiceBox.getItems().clear();
            exportKeyChoiceCombobox.getItems().clear();
            allKeys.forEach(exportedKeyData -> {
                if (exportedKeyData.getIsMasterKey()) {
                    signChoiceBox.getItems().add(parseExportedKeyDataToChoiceBoxReadableText(exportedKeyData));
                    exportKeyChoiceCombobox.getItems().add(parseExportedKeyDataToChoiceBoxReadableText(exportedKeyData));
                }
                EncryptionWrapper wrapper = new EncryptionWrapper();
                wrapper.setElement(exportedKeyData);
                wrapper.setSelected(false);
                publicKeyEncryptionChoiceTableView.getItems().add(wrapper);
                certificateTableTableView.getItems().add(exportedKeyData);
            });
        });

        /**
         * TODO [INTEGRACIJA] Tu treba da stoji logika za dohvatanje svih kljuceva - Uradjeno [TESTIRATI]
         */
        ArrayList<ExportedKeyData> exportedKeyData = keyManager.generatePublicKeyList();
        for (ExportedKeyData element :
                exportedKeyData) {
            addKeyToAllKeys(element);
        }

        // Referencirati ovu metodu
        createCertificatesListView();

        // TODO? [INTEGRACIJA] Dodati sve kljuceve u for-petlji --- Mozda ima addALL? - [POTENCIJALNO NE TREBA]

        // Referencirati metodu
        initializePublicKeyEncryptionKeys();

        // TODO? [INTEGRACIJA] Za sve kljuceve KOJI SU PUBLIC (potrebna isMaster provera, a sta ako sifrujemo za neki drugi nas privatni kljuc? mozda ne treba provera). Treba napraviti Wrapper objekat i staviti false na sve!!!  - [POTENCIJALNO NE TREBA]
        /**
         * Wrapper objekat je da bi checkbox radio!!!
         */
        // Ne treba ovaj deo, dodajemo sve u allKeys i onda on sve to iscitava
//        EncryptionWrapper ew = new EncryptionWrapper();
//        ew.setSelected(false);
//        ew.setElement(dummyData);
//        publicKeyEncryptionChoiceTableView.getItems().add(ew);


        // TODO? [INTEGRACIJA] Tu treba popuniti takodje i ostale choiceBox-ove gde mozemo da biramo kljuceve  - [POTENCIJALNO NE TREBA]
    }

    private void removeKeyFromObservableKeyCollection(ExportedKeyData keyData) {
        removeKeyFromObservableKeyCollection(keyData.getKeyID());
    }
    private void removeKeyFromObservableKeyCollection(long keyID) {
        for (int i = 0; i < allKeys.size(); ++i) {
            if (allKeys.get(i).getKeyID() == keyID) {
                allKeys.remove(i);
                break;
            }
        }
    }

    /**
     * Kao sto ime naslucuje, parsirramo odabran algoritam is choice box u nesto sto API moze da koristi
     *
     * @param selection
     * @return
     */
    private RSA.KeySizes parseRSAAlgorithmSelection(String selection) {
        return rsaKeySizesHashMap.get(selection);
    }

    /**
     * Kao sto ime naslucuje, parsirramo odabran algoritam is choice box u nesto sto API moze da koristi
     *
     * @param selection
     * @return
     */
    private int parseSymmetricKeyAlgorithmSelection(String selection) {
        return symmetricAlgorithmsHashMap.get(selection);
    }

    // TODO [INTEGRACIJA] implementirati metodu za dobijanje kljuca iz potpisa, potipis ima informaciju o KEYID -- Secret ili public???
    private PGPSecretKey parseSignatureSelectionToKey(String signature) {
        String[] elements = signature.split(", ");
        String userName = elements[0];
        String email = elements[1];
        BigInteger keyID = new BigInteger(elements[2], 16);

        // TODO [INTEGRACIJA] Pretraga trazenog kljuca, vracanje istog;
        // --------| CODE GOES HERE
        try {
            PGPSecretKey pgpSecretKey = keyManager.getSecretKeyById(keyID.longValue());
            return pgpSecretKey;
        } catch (PGPException e) {
            showErrorDialog("Error getting key", "Error encountered while searching for key with ID " + keyID, e.getMessage());
        }
        // --------|

        return null;
    }

    /**
     * Vrsi konverziju koja je pogodna za choicebox-ove kako bi se kasnije uradila konverzija za signature
     * <p>
     * KORISTITI ZA SVE CHOICE BOX-OVE!!
     *
     * @param exportedKeyData
     * @return
     */
    private String parseExportedKeyDataToChoiceBoxReadableText(ExportedKeyData exportedKeyData) {
        String username = exportedKeyData.getUserName();
        String email = exportedKeyData.getEmail();
        String keyID = exportedKeyData.getKeyIDHex();

        return String.format("%s, %s, %s", username, email, keyID);

    }

    /**
     * Encrypt message and send based on selected parameters
     *
     * @param actionEvent
     */
    public void sendAction(ActionEvent actionEvent) {
        String fileLocation = browseFileLocationTextField.getText();
        File file = new File(fileLocation);
        if (!file.exists()) {
            showErrorDialog("Input parameters are incorrrect!",
                    "Incorrect filepath!",
                    "The file with the provided filepath doesn't exist or the filepath isnt correct!");
            return;
        }

        boolean useEncryption = useEncryptionCheckBox.isSelected();
        boolean sign = signCheckBox.isSelected();
        boolean useCompression = compressionCheckBox.isSelected();
        boolean base64 = base64ConversionCheckBox.isSelected();

        String signature = (String) signChoiceBox.getValue();
        String encryptionAlgorithm = (String) encryptionAlgorithmsChoiceBox.getValue();

        int algorithm = parseSymmetricKeyAlgorithmSelection(encryptionAlgorithm);

        // Ako smo se opredelili za potpis, moramo da vidimo da li je signature prazan
        // Signature treba da se generise na osnovu Username, mail i keyID!!!!
        // TODO [INTEGRACIJA] Parsirati nase kljuceve (samo privatne) da se izlistaju po definisanoj strukturi i parsirati

        if (sign && signature == null) {
            showErrorDialog("Input parameters are incorrrect!",
                          "Incorrect signature",
                            "You have to specify Key for the signature!");
            return;
        }

        // Ovo je lista gde stavljamo ljude za koje sifrujemo poruku
        ArrayList<EncryptionWrapper> data = new ArrayList<>();


        // TODO [INTEGRACIJA] Ovde pocinje deo za implementaciju sifrovanja, potpisivanja i zipovanja, zavisi od API-ja
        if (useEncryption) {
            /**
             * Ovaj deo je napravljen tako da mi dohvatamo sve izlistane u table-view za sifrovanje (slanje) akko je
             * stiklirano da zelimo enkripciju.
             *
             * Encryption wrapper je klasa napravljena da se sastoji od ExtractedKeyData i boolean polja koje
             * se vezuje za checkbox u tabeli. Tako proveravamo da li saljemo tom i tom liku
             */
            for (int i = 0; i < publicKeyEncryptionChoiceTableView.getItems().size(); i++) {
                EncryptionWrapper temp = (EncryptionWrapper) publicKeyEncryptionChoiceTableView.getItems().get(i);
                if (temp.isSelected())
                    data.add(temp);
            }

            // Ako nikoga ne stikliramo
            if (data.size() == 0) {
                showErrorDialog("Input parameters are incorrrect!",
                                "Invalid number of recipients!",
                                "You have to specify everyone that you want to receive your message !");
                return;
            }
        }
        // TODO [INTEGRACIJA] Uraditi algoritam za slanje u zavisnosti od odabranih parametara


    }

    /**
     * Promenimo stanje ChoiceBox-a na disabled ako je odcekirano (za use encryption)
     *
     * @param actionEvent
     */
    public void useEncryptionChangeAction(ActionEvent actionEvent) {
        encryptionAlgorithmsChoiceBox.setDisable(!useEncryptionCheckBox.isSelected());
        publicKeyEncryptionChoiceTableView.setDisable(!useEncryptionCheckBox.isSelected());
    }

    /**
     * Promenimo stanje ChoiceBox-a na disabled ako je odcekirano ( za sign)
     *
     * @param actionEvent
     */
    public void signChangeAction(ActionEvent actionEvent) {
        signChoiceBox.setDisable(!signCheckBox.isSelected());
    }

    /**
     * Stavljeno za svaki slucaj, ne koristi se
     *
     * @param actionEvent
     */
    public void compressionChangeAction(ActionEvent actionEvent) {
        // Empty
    }

    /**
     * Stavljeno za svaki slucaj, ne koristi se
     *
     * @param actionEvent
     */
    public void base64ConversionChangeAction(ActionEvent actionEvent) {
        // Empty
    }
    // End - Encryption

    /**
     * Samo pravimo kolone za ispis svih sertifikata, nis spec
     */
    private void createCertificatesListView() {
        TableColumn nameColumn = new TableColumn("Name");
        nameColumn.setCellValueFactory(new PropertyValueFactory<>("userName"));
        TableColumn emailColumn = new TableColumn("Email");
        emailColumn.setCellValueFactory(new PropertyValueFactory<>("email"));
        TableColumn validFrom = new TableColumn("Valid from");
        validFrom.setCellValueFactory(new PropertyValueFactory<>("validFrom"));
        TableColumn validUntil = new TableColumn("Valid Until");
        validUntil.setCellValueFactory(new PropertyValueFactory<>("validUntil"));
        TableColumn keyId = new TableColumn("Key ID");
        keyId.setCellValueFactory(new PropertyValueFactory<>("keyIDHex"));
        TableColumn isMaster = new TableColumn("Master Key");
        isMaster.setCellValueFactory(new PropertyValueFactory<>("isMasterKey"));
        certificateTableTableView.getColumns().addAll(nameColumn, emailColumn, validFrom, validUntil, keyId, isMaster);

    }

    /**
     * Dodajemo kolone u tabelu za enkripciju, treba napraviti posebnu kolonu za checkbox
     * <a href="https://stackoverflow.com/a/36953229">Link</a> za checkbox dodavanje, samo prebaceno u lambda
     * <p>
     * Property value factory implicitno poziva za klasu koju prosledjujes prilikom dodavanja u table
     * gettere na osnovu field-name-a koji zapises ovde.
     * <p>
     * Tacnije - poziva bilo koju metodu sa konvencijom Camel-Case getFieldname()... Ne mora da bude polje u samoj
     * klasi, bitna je konvencija imenovanja. Referencirati Wrapper klasu i pogledati primer gettera! Polje je Extracted
     * key data i onda vracamo iz tog objekta sta nam je potrebno
     */
    private void initializePublicKeyEncryptionKeys() {
        TableColumn encryptionCheckbox = new TableColumn("Encrypt");
        encryptionCheckbox.setCellValueFactory((Callback<TableColumn.CellDataFeatures<EncryptionWrapper, CheckBox>, ObservableValue<CheckBox>>) arg0 -> {
            EncryptionWrapper user = arg0.getValue();
            CheckBox checkBox = new CheckBox();
            checkBox.selectedProperty().setValue(user.isSelected());
            checkBox.selectedProperty().addListener((ov, old_val, new_val) -> user.setSelected(new_val));
            return new SimpleObjectProperty<>(checkBox);
        });
        TableColumn encryptionName = new TableColumn("Name");
        encryptionName.setCellValueFactory(new PropertyValueFactory<>("userName"));
        TableColumn encryptionEmail = new TableColumn("Email");
        encryptionEmail.setCellValueFactory(new PropertyValueFactory<>("email"));
        TableColumn encryptionKeyId = new TableColumn("Key ID");
        encryptionKeyId.setCellValueFactory(new PropertyValueFactory<>("keyIDHex"));

        publicKeyEncryptionChoiceTableView.getColumns().addAll(encryptionCheckbox, encryptionName, encryptionEmail, encryptionKeyId);
    }

    /**
     * Ovo je pomocna metoda za dodavanje ExportedKeyData u "kolekciju" iliti observable listu svih kljuceva
     * u sistemu. Odvojeno je ovako zbog potencijalne provere postojanja istog kljuca
     *
     * @param data
     */
    private void addKeyToAllKeys(ExportedKeyData data) {
        // TODO [INTEGRACIJA] Da li treba proveravati da postoji kljuc sa istim parametrima???

        // Provera

        allKeys.add(data);
    }

    /**
     * Otvara file search dialog i upisuje u textfield
     *
     * @param actionEvent
     */
    public void browseFiileAction(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Resource File");
        File file = fileChooser.showOpenDialog(Main.mainReference.currentStage);
        if (file != null) {
            browseFileLocationTextField.setText(file.getAbsolutePath());
        }
    }

    /**
     * Elegantan nacin za unos password-a, obavezno koristiti za dekripcije/enkripcije, sta vec
     *
     * @return
     */
    private String passwordInputDialogBoxWithText(String text) {
        PasswordDialog pd = new PasswordDialog(text);
        Optional<String> result = pd.showAndWait();
        AtomicReference<String> passwordResult = new AtomicReference<>(null);
        result.ifPresent(password -> passwordResult.set(password));
        return passwordResult.get();
    }
    /**
     * Elegantan nacin za unos password-a, obavezno koristiti za dekripcije/enkripcije, sta vec
     *
     * @return
     */
    private String passwordInputDialogBox() {
        PasswordDialog pd = new PasswordDialog();
        Optional<String> result = pd.showAndWait();
        AtomicReference<String> passwordResult = new AtomicReference<>();
        result.ifPresent(password -> passwordResult.set(password));
        return passwordResult.get();
    }

    /**
     * Ova metoda ima zadatak da izvrsi dekripciju fajla i izvrsi njenu verifikaciju.
     * Stavio sam pocetan kod samo za proveru validnosti fajla, ostatak je sustinski API
     *
     * @param actionEvent
     */
    public void startDecriptionAndVerificationButton(ActionEvent actionEvent) {
        String fileToDecrypt = browseDecryptionFileLocationTextField.getText();
        File file = new File(fileToDecrypt);
        if (!file.exists()) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect filepath", "You have to specify the correct file path and/or the file doesn't exist!");
            return;
        }
        try (InputStream stream = new FileInputStream(file)) {

            // TODO [INTEGRACIJA] Koriscenje funkcionalnosti za dekripciju i verifikaciju!


            // --------| CODE GOES HERE
            // ....
            // --------|
            // displayDecriptionAndVerificationOutputTextField.setText ssa rezultatom
            // Eventualno dialog box sa info da li je uspeo da verifikuje

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Otvara file search dialog i upisuje u textfield
     *
     * @param actionEvent
     */
    public void chooseDecryptionFileLocation(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Resource File");
        File file = fileChooser.showOpenDialog(Main.mainReference.currentStage);
        if (file != null) {
            decryptionFileLocationTextField.setText(file.getAbsolutePath());
        }
    }

    /**
     * Ovo treba da sacuva dekriptovan fajl. Postavlja se pitanje -- Kako cuvati dekriptovan fajl. Prosiriti
     * Controller klasu po potrebi
     *
     * @param actionEvent
     */
    public void saveDecryptedFIle(ActionEvent actionEvent) {
        String fileLocation = decryptionFileLocationTextField.getText();
        if (fileLocation.length() == 0) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect filepath", "You have to specify the correct file path!");
            return;
        }
        File newFile = new File(fileLocation);

        try (OutputStream os = new FileOutputStream(newFile)) {
            newFile.createNewFile();

            // TODO [INTEGRACIJA] Implementirati cuvanje dekriptovanog fajla sa OutputStreamom
            // --------| CODE GOES HERE
            // ....
            // --------|
        } catch (IOException e) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect filepath", "You have to specify the correct file path!");
        }
    }

    /**
     * Otvara directory chooser (TO ZNACI DA TREBA POSTAVITI NEKAKO NAZIV .asc FAJLA INTERNO)
     * Putanju printuje u textbox
     *
     * @param actionEvent
     */
    public void chooseExportKeysFileLocation(ActionEvent actionEvent) {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Choose Directory");
        File file = directoryChooser.showDialog(Main.mainReference.currentStage);
        if (file != null) {
            exportFileLocationTextField.setText(file.getAbsolutePath());
        }
    }

    /**
     * Vrsi sam EXPORT kljuca, dohvata se kljuc iz textboca i dohvata se vrednost odabranog kljuca za export
     *
     * @param actionEvent
     */
    public void executeExportKey(ActionEvent actionEvent) {
        String destination = exportFileLocationTextField.getText();
        String signature = (String) exportKeyChoiceCombobox.getValue(); // konverzija u ExportedData

        if (signature == null) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect key", "You have to specify the correct key!");
            return;
        }

        // TODO [INTEGRACIJA] Obavezno proveriti postojanost kljuca
        PGPSecretKey secretKey = parseSignatureSelectionToKey(signature);

        if(secretKey == null)
            return;

        if (destination.length() == 0) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect filepath", "You have to specify the correct filepath!");
            return;
        }

        String fileName = String.format("%s[%s]_%s.asc",
                secretKey.getUserIDs().next(), Long.toHexString(secretKey.getKeyID()),(new Date().toString().replace(' ', '_')));
        File outputFile = new File(destination + "/" + fileName);
        try (OutputStream os = new FileOutputStream(outputFile)) {
            outputFile.createNewFile();
            // TODO [INTEGRACIJA] Algoritam za export kljuca
            keyManager.exportPublicKey(secretKey.getKeyID(), os);
            showSuccessDialog("Successfully exported key", "Key selection was successfully exported", "The key is located at " + outputFile.getAbsolutePath());
        }  catch (IOException e) {
            showErrorDialog("Error while trying to import public key!", "There was an unexpected error with the IO Stream!", e.getMessage());
        } catch (PGPException e) {
            showErrorDialog("Error while trying to import public key!", "PGP exception occurred!", e.getMessage());
        }
    }

    /**
     * Napravljena za svaki slucaj
     *
     * @param actionEvent
     */
    public void keyChoiceComboboxAction(ActionEvent actionEvent) {
        // Empty...
    }

    /**
     * Biramo fajl koji sadrzi kljuc za import
     *
     * @param actionEvent
     */
    public void browseImportSecretKey(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Resource File");
        File file = fileChooser.showOpenDialog(Main.mainReference.currentStage);
        if (file != null) {
            pathToImportKeyFileTextField.setText(file.getAbsolutePath());
        }
    }

    /**
     * Ova metoda treba da upise sam kljuc u keyring
     *
     * @param actionEvent
     */
    public void executeImportSecretKey(ActionEvent actionEvent) {
        String importPath = pathToImportKeyFileTextField.getText();
        File file = new File(importPath);
        if (!file.exists()) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect path to key", "You have have to specify the correct path to the secret key file!");
            return;
        }
        try (InputStream is = new FileInputStream(file)) {
            // TODO [INTEGRACIJA] Ovde treba staviti logiku za unos privatnog kljuca -- Uradjeno [Testirati]
            ExportedKeyData keyData = keyManager.importSecretKeyring(is);
            addKeyToAllKeys(keyData);
            showSuccessDialog("Key add success!", "The key was successfully added",
                    String.format("Secret key for user %s <%s> was successfully imported. Key ID: %s",
                    keyData.getUserName(), keyData.getEmail(), keyData.getKeyIDHex()));
            keyManager.saveKeys();
        } catch (FileNotFoundException e) {
            showErrorDialog("Error while trying to import public key!", "There was an error with the input stream!", e.getMessage());
        } catch (IOException e) {
            showErrorDialog("Error while trying to import public key!", "There was an unexpected error with the IO Stream!", e.getMessage());
        } catch (PGPException e) {
            showErrorDialog("Error while trying to import public key!", "PGP exception occurred!", e.getMessage());
        }

    }


    /**
     * Biramo fajl koji sadrzi kljuc za import
     *
     * @param actionEvent
     */
    public void browseImportPublicKey(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Resource File");
        File file = fileChooser.showOpenDialog(Main.mainReference.currentStage);
        if (file != null) {
            publicKeyFIleLocationTextField.setText(file.getAbsolutePath());
        }
    }

    /**
     * Logicno - ovde treba da se izxvrsi sam unos javnog kljuca
     *
     * @param actionEvent
     */
    public void executeImportPublicKey(ActionEvent actionEvent) {
        String importPath = publicKeyFIleLocationTextField.getText();
        File file = new File(importPath);
        if (!file.exists()) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect path to key", "You have have to specify the correct path to the secret key file!");
            return;
        }
        try (InputStream is = new FileInputStream(file)) {
            // TODO [INTEGRACIJA] Ovde treba staviti logiku za unos javnog kljuca - Uradjeno [TESTIRATI]
            ExportedKeyData keyData = keyManager.importPublicKeyring(is);
            addKeyToAllKeys(keyData);
            showSuccessDialog("Key add success!", "The key was successfully added",
                    String.format("Key for user %s <%s> was successfully imported. Key ID: %s",
                            keyData.getUserName(), keyData.getEmail(), keyData.getKeyIDHex()));
            keyManager.saveKeys();
        } catch (FileNotFoundException e) {
            showErrorDialog("Error while trying to import public key!", "There was an error with the input stream!", e.getMessage());
        } catch (IOException e) {
            showErrorDialog("Error while trying to import public key!", "There was an unexpected error with the IO Stream!", e.getMessage());
        } catch (PGPException e) {
            showErrorDialog("Error while trying to import public key!", "PGP exception occurred!", e.getMessage());
        }
    }

    /**
     * Pomocna metoda za mathc-ovanje regex-a za mejl
     *
     * @param mail
     * @return
     */
    private boolean checkMail(String mail) {
        String regex = "^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(mail);
        return matcher.matches();
    }

    /**
     * Kao sto ime nagovestava -- Ova metoda ima zadatak da izgenerise novi keypair
     *
     * @param actionEvent
     */
    public void generateNewKeyPairButton(ActionEvent actionEvent) {
        String name = newKeyPairName.getText();
        String email = newKeyPairEmail.getText();
        String password = newKeyPairPassword.getText();
        String algorithm = (String) newKeyPairAlgorithm.getValue();
        RSA.KeySizes rsaSize = parseRSAAlgorithmSelection(algorithm);
        if (name.length() == 0) {
            showErrorDialog("Incorrect parameter input!", "Name input incorrect!", "The name parameter must be non-empty!");
            return;
        }

        if (!checkMail(email)) {
            showErrorDialog("Incorrect parameter input!", "Email input incorrect!", "The email parameter must be non-empty and has to have the format <username>@<domain>!");
            return;
        }

        if (password.length() < 8) {
            showErrorDialog("Incorrect parameter input!", "Password input incorrect!", "Password has to be at least 8 characters!");
            return;
        }

        if (algorithm == null) {
            showErrorDialog("Incorrect parameter input!", "Algorithm input incorrect!", "You have to choose an algorithm!");
            return;
        }

        // TODO [INTEGRACIJA] Izvrsavanje dodavanja novog kljuca -- Uradjeno [TESTIRATI]
        if (!showConfirmationDialog("Are you sure?",
                "Are the values you entered valid?",
                String.format("- %s\n- %s\n- %s", name, email, algorithm))) {
        }
        String reentered = passwordInputDialogBoxWithText("Please reenter your password");

        if (reentered == null)
            return;

        if (!reentered.equals(password)) {
            showErrorDialog("Error confirming passwords", "", "Passwords do not match");
            return;
        }
        try {
        PGPKeyPair masterKey = RSA.RSA_GetUtility()
                .RSA_SetKeySize(rsaSize)
                .RSA_PGPKeyGenerator();
        PGPKeyPair signingKey = RSA.RSA_GetUtility()
                .RSA_SetKeySize(rsaSize)
                .RSA_PGPKeyGenerator();
        ExportedKeyData keyData = keyManager.makeKeyPairs(masterKey, signingKey, name, email, password);
        addKeyToAllKeys(keyData);
        showSuccessDialog("Success!", "Key generation was a success!", "The key was successfully generated. The Key ID is: " + keyData.getKeyIDHex());
        } catch (Exception e) {
            showErrorDialog("Error!", "An error occured while trying to generate new key-pair", e.getMessage());
        }
    }

    /**
     * Otvara se file chooser koji postavlja vrednost apsolutne putanje u textbox
     *
     * @param actionEvent
     */
    public void browseDecryptionFileAction(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Resource File");
        File file = fileChooser.showOpenDialog(Main.mainReference.currentStage);
        if (file != null) {
            browseDecryptionFileLocationTextField.setText(file.getAbsolutePath());
        }
    }

    /**
     * Ova metoda se poziva sa tab-a view certificates, klikom desnog klika na neki sertifikat i odabirom
     * za export kljuca. Ova metoda treba da export-uje javni kljuc. Imamo dve metode za export javnog kljuca, da!
     * <p>
     * Treba prikazati uspesnost
     *
     * @param actionEvent
     */
    public void contextMenuExportKey(ActionEvent actionEvent) {
        ExportedKeyData keyData = (ExportedKeyData) certificateTableTableView.getSelectionModel().getSelectedItem();
        if (keyData != null) {
            // TODO [INTEGRACIJA] Obrada za export JAVNOG kljuca iz liste svih sertifikata na desni klik -- Uradjeno [TESTIRATI]
            DirectoryChooser directoryChooser = new DirectoryChooser();
            directoryChooser.setTitle("Choose where to export");
            File file = directoryChooser.showDialog(Main.mainReference.currentStage);
            if (file != null) {
                String fileName = String.format("%s[%s]_%s_%s.asc",
                        keyData.getUserName(), keyData.getEmail(), keyData.getKeyIDHex(),(new Date().toString().replace(' ', '_')));
                file = new File(file.getAbsolutePath() + "/" + fileName);
                try {
                    file.createNewFile();
                    OutputStream fos = new FileOutputStream(file);
                    keyManager.exportPublicKey(keyData.getKeyID(), fos);
                    showSuccessDialog("Export finished successfully!", "The key was successfully exported!",
                            "The file can be found at: " + file.getAbsolutePath());
                } catch (IOException | PGPException e) {
                    showErrorDialog("Error!", "There was an error while trying to export key "+keyData.getKeyIDHex()+"!", e.getMessage());
                }


            }
        }
    }

    /**
     * Ova metoda se poziva sa tab-a view certificates, klikom desnog klika na neki sertifikat i odabirom
     * za brisanje kljuca. TU obavezno treba da se pozove metoda koja generise dialog za unos passworda i provera ispravnosti istog, ako je master,
     * ako nije master samo treba prikazati dijalog za potvrdu selekcije
     *
     * @param actionEvent
     */
    public void contextMenuDeleteKey(ActionEvent actionEvent) {
        ExportedKeyData keyData = (ExportedKeyData) certificateTableTableView.getSelectionModel().getSelectedItem();
        if (keyData != null) {
            // TODO [INTEGRACIJA] Obrada za delete kljuca iz liste svih sertifikata na desni klik -- OBAVEZNO TU KORISTITI Password Dialog METODU ZA PROVERU PASSWORD AKO JE ISMASTER!!!!
            if (keyData.getIsMasterKey()) {
                String password = passwordInputDialogBox();
                try {
                    keyManager.removeSecretKey(keyData.getKeyID(), password);
                    removeKeyFromObservableKeyCollection(keyData);
                    keyManager.saveKeys();
                } catch (PGPException e) {
                    showErrorDialog("Error!", "There was an error while trying to remove key "+keyData.getKeyIDHex()+"!", e.getMessage());
                } catch (IncorrectKeyException e) {
                    showErrorDialog("Error!", "Incorrect password!", e.getMessage());
                } catch (IOException e) {
                    showErrorDialog("Error!", "Error saving keys!", e.getMessage());
                }
            } else {
                try {
                    keyManager.removePublicKey(keyData.getKeyID());
                    removeKeyFromObservableKeyCollection(keyData.getKeyID());
                    keyManager.saveKeys();
                } catch (PGPException e) {
                    showErrorDialog("Error!", "There was an error while trying to remove key "+keyData.getKeyIDHex()+"!", e.getMessage());
                } catch (IOException e) {
                    showErrorDialog("Error!", "There was an error while trying to remove key!", e.getMessage());
                }
            }
        }
    }

    /**
     * Ova metoda treba da izvrsi backup/export privatnog/tajnog kljuca.
     * Dozvoliti uz pitanje za password!!!!
     *
     * @param actionEvent
     */
    public void contextMenuBackupKey(ActionEvent actionEvent) {
        ExportedKeyData keyData = (ExportedKeyData) certificateTableTableView.getSelectionModel().getSelectedItem();
        if (keyData != null) {
            // Ne moze secret key backup ako nije secret key
            if (!keyData.getIsMasterKey()) {
                showErrorDialog("Incorrect key selection!", "Cannot backup public key!", "You cant invoke master key backup on public keys!");
                return;
            } else {
                // TODO [INTEGRACIJA] Obrada za export TAJNOG kljuca iz liste svih sertifikata na desni klik, obavezno provera password-a - Uradjeno [TESTIRATI]
                DirectoryChooser directoryChooser = new DirectoryChooser();
                directoryChooser.setTitle("Choose where to export");
                File file = directoryChooser.showDialog(Main.mainReference.currentStage);
                if (file != null) {
                    String fileName = String.format("%s[%s]_%s_%s_SECRET.asc",
                            keyData.getUserName(), keyData.getEmail(), keyData.getKeyIDHex(), (new Date().toString().replace(' ', '_')));
                    file = new File(file.getAbsolutePath() + "/" + fileName);
                    try {
                        file.createNewFile();
                        OutputStream fos = new FileOutputStream(file);
                        keyManager.exportSecretKey(keyData.getKeyID(), fos);
                        showSuccessDialog("Export finished successfully!", "The key was successfully exported!",
                                "The file can be found at: " + file.getAbsolutePath());
                    } catch (IOException | PGPException | KeyNotFoundException e) {
                        showErrorDialog("Error!", "There was an error while trying to export key "+keyData.getKeyIDHex()+"!", e.getMessage());
                        if (e instanceof KeyNotFoundException) {
                            removeKeyFromObservableKeyCollection(keyData);
                        }
                    }
                }
            }
        }
    }



    /******************* DISPLAY DIALOGS **********************/
    /**
     * Izvrsava ispisivanje
     *
     * @param title
     * @param header
     * @param text
     * @param type
     */
    private void displayDialog(String title, String header, String text, Alert.AlertType type) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(header);
        alert.setContentText(text);
        alert.showAndWait();

    }
    /**
     * Poziva metodu za ispis dialoga, prikaz, kako god.
     * Tip se zakljucuje iz naziva metode
     *
     * @param title
     * @param header
     * @param text
     */
    private void showErrorDialog(String title, String header, String text) {
        displayDialog(title, header, text, Alert.AlertType.ERROR);
    }

    private boolean showConfirmationDialog(String title, String header, String text) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle(title);
        alert.setHeaderText(header);
        alert.setContentText(text);
        ButtonType okButton = new ButtonType("Yes", ButtonBar.ButtonData.YES);
        ButtonType noButton = new ButtonType("No", ButtonBar.ButtonData.NO);
        alert.getButtonTypes().setAll(okButton, noButton);
        AtomicBoolean returnValue = new AtomicBoolean(false);
        alert.showAndWait().ifPresent(type -> {
            if (type.getButtonData() == ButtonBar.ButtonData.YES) {
                returnValue.set(true);
            } else {
                returnValue.set(false);
            }
        });
        return returnValue.get();
    }

    /**
     * Poziva metodu za ispis dialoga, prikaz, kako god.
     * Tip se zakljucuje iz naziva metode
     *
     * @param title
     * @param header
     * @param text
     */
    private void showWarningDialog(String title, String header, String text) {
        displayDialog(title, header, text, Alert.AlertType.WARNING);
    }
    /**
     * Poziva metodu za ispis dialoga, prikaz, kako god.
     * Tip se zakljucuje iz naziva metode
     *
     * @param title
     * @param header
     * @param text
     */
    private void showSuccessDialog(String title, String header, String text) {
        displayDialog(title, header, text, Alert.AlertType.INFORMATION);
    }

}