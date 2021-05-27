package sample;

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

import java.io.*;
import java.util.*;
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
    public ComboBox exportKeyChoiceCombobox;
    public ComboBox newKeyPairAlgorithm; // ne trebaju kljucevi
    public ChoiceBox encryptionAlgorithmsChoiceBox; // Ne trebaju kljucevi
    public ChoiceBox signChoiceBox;
    public TableView certificateTableTableView;
    public TableView publicKeyEncryptionChoiceTableView;

    public Button browseDecryptionFileChooserTriggerButton;
    public TextField browseDecryptionFileLocationTextField;
    public TextArea displayDecriptionAndVerificationOutputTextField;
    public Button decryptAndVerifyButton;
    public Button saveDecryptionFileLocationButton;
    public TextField decryptionFileLocationTextField;
    public Button saveDecryptionFileButton;
    public Button browseExportKeysFileButton;
    public TextField exportFileLocationTextField;
    public Button executeExportKeyButton;
    public Button browseImportSecretKeyButton;
    public TextField pathToImportKeyFileTextField;
    public Button executeImportSecretKeyButton;
    public Button browseImportPublicKeyButton;
    public Button executeImportPublicKeyButton;
    public TextField publicKeyFIleLocationTextField;
    public TextField newKeyPairName;
    public TextField newKeyPairEmail;
    public PasswordField newKeyPairPassword;
    public Button generateNewKeyPairButton;
    public TextField browseFileLocationTextField;
    public CheckBox useEncryptionCheckBox;
    public CheckBox signCheckBox;
    public CheckBox compressionCheckBox;
    public CheckBox base64ConversionCheckBox;
    public Button sendButton;
    public Button browseFileChooserTriggerButton;
    private List<String> symmetricAlgorithms = new ArrayList<>();
    private List<String> asymmetricAlgorithms = new ArrayList<>();
    private ObservableList<ExportedKeyData> allKeys = FXCollections.observableArrayList();

    // TODO [INTEGRACIJA] KeyManager keyManager;

    /**
     * TODO [INTEGRACIJA] Izbrisati definiciju enuma, korisiti vec implementiranu u RSA.java klasi
     * <p>
     * Mock za vec implementiranu klasu
     */
    public static enum KeySizes {
        RSA1024(1024),
        RSA2048(2048),
        RSA4096(4096);


        private final int keySize;

        KeySizes(int keySize) {
            this.keySize = keySize;
        }

        public int getKeySize() {
            return this.keySize;
        }
    }

    // Sluzi za parsiranje stringa prilikom odabira iz choice box-a za novi tajni kljuc
    private HashMap<String, KeySizes> rsaKeySizesHashMap = new HashMap<>();

    // TODO [INTEGRACIJA] napraviti slican hash za simetricne algoritme, takodje dodati u inicijalizaciju
    // ---------| CODE GOES HERE
    // ...
    // ---------|


    // Inicijalizacija neophodnih struktura podataka za ispis u FX komponente
    public Controller() {
        String rsa1024 = "RSA 1024";
        String rsa2048 = "RSA 2048";
        String rsa4096 = "RSA 4096";

        symmetricAlgorithms.add("Triple DES");
        symmetricAlgorithms.add("IDEA");

        asymmetricAlgorithms.add(rsa1024);
        asymmetricAlgorithms.add(rsa2048);
        asymmetricAlgorithms.add(rsa4096);

        rsaKeySizesHashMap.put(rsa1024, KeySizes.RSA1024);
        rsaKeySizesHashMap.put(rsa2048, KeySizes.RSA2048);
        rsaKeySizesHashMap.put(rsa4096, KeySizes.RSA4096);

        /**
         * TODO [INTEGRACIJA] keyManager = new KeyManager();
         * TODO [INTEGRACIJA] Main.keyManagerReference = keyManager;
         */

    }

    /**
     * Izvrsava ispisivanje
     *
     * @param title
     * @param header
     * @param text
     * @param type
     */
    private void displayDialog(String title, String header, String text, Alert.AlertType type) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(title);
        alert.setHeaderText(header);
        alert.setContentText(text);
        alert.showAndWait();

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
        displayDialog(title, header, text, Alert.AlertType.CONFIRMATION);
    }

    /**
     * Kao sto ime naslucuje, parsirramo odabran algoritam is choice box u nesto sto API moze da koristi
     *
     * @param selection
     * @return
     */
    private KeySizes parseRSAAlgorithmSelection(String selection) {
        return rsaKeySizesHashMap.get(selection);
    }

    /**
     * TODO [INTEGRACIJA] Implementirati analogno parseRSAAlgorithmSelection metodi iznad
     * Kao sto ime naslucuje, parsirramo odabran algoritam is choice box u nesto sto API moze da koristi
     *
     * @param selection
     * @return
     */
    private Object parseSymmetricKeyAlgorithmSelection(String selection) {
        return null;
    }

    // TODO [INTEGRACIJA] implementirati metodu za dobijanje kljuca iz potpisa, potipis ima informaciju o KEYID
    private Object parseSignatureSelectionToKey(String signature) {
        String[] elements = signature.split(", ");
        String userName = elements[0];
        String email = elements[1];
        String keyID = elements[2];

        // TODO [INTEGRACIJA] Pretraga trazenog kljuca, vracanje istog;
        // --------| CODE GOES HERE
        // ....
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
        long keyID = exportedKeyData.getKeyID();

        return String.format("%s, %s, %d", username, email, keyID);

    }

    public void sendAction(ActionEvent actionEvent) {
        String fileLocation = browseFileLocationTextField.getText();
        File file = new File(fileLocation);
        if (!file.exists()) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect filepath!", "The file with the provided filepath doesn't exist or the filepath isnt correct!");
            return;
        }

        boolean useEncryption = useEncryptionCheckBox.isSelected();
        boolean sign = signCheckBox.isSelected();
        boolean useCompression = compressionCheckBox.isSelected();
        boolean base64 = base64ConversionCheckBox.isSelected();

        String signature = (String) signChoiceBox.getValue();
        String encryptionAlgorithm = (String) encryptionAlgorithmsChoiceBox.getValue();

        // TODO [INTEGRACIJA] Uraditi parsiranje enkripcionog algoritma uz pomoc parseSymmetricKeyAlgorithmSelection
        // --------| CODE GOES HERE
        // ....
        // --------|

        // Ako smo se opredelili za potpis, moramo da vidimo da li je signature prazan
        // Signature treba da se generise na osnovu Username, mail i keyID!!!!
        // TODO [INTEGRACIJA] Parsirati nase kljuceve (samo privatne) da se izlistaju po definisanoj strukturi i parsirati

        if (sign && signature == null) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect signature", "You have to specify for the signature!");
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
                showErrorDialog("Input parameters are incorrrect!", "Invalid number of recipients!", "You have to specify everyone that you want to receive your message !");
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
        keyId.setCellValueFactory(new PropertyValueFactory<>("keyID"));
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
        encryptionKeyId.setCellValueFactory(new PropertyValueFactory<>("keyID"));

        publicKeyEncryptionChoiceTableView.getColumns().addAll(encryptionCheckbox, encryptionName, encryptionEmail, encryptionKeyId);
    }

    /**
     * Ovo je pomocna metoda za dodavanje ExportedKeyData u "kolekciju" iliti observable listu svih kljuceva
     * u sistemu. Odvojeno je ovako zbog potencijalne provere postojanja istog kl;jjuca
     *
     * @param data
     */
    private void addKeyToAllKeys(ExportedKeyData data) {
        // TODO [INTEGRACIJA] Da li treba proveravati da postoji kljuc sa istim parametrima???

        // Provera

        allKeys.add(data);
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
        // TODO [INTEGRACIJA] Testirati ovaj Listener
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
         * TODO [INTEGRACIJA] Tu treba da stoji logika za dohvatanje svih kljuceva u sistemu radi ispisa, za sad samo dummy
         */
        ExportedKeyData dummyData = new ExportedKeyData();
        dummyData.setEmail("stefant@98.com");
        dummyData.setUserName("Stefan Teslic");
        dummyData.setKeyID(123123123);
        dummyData.setValidFrom(new Date());
        dummyData.setValidUntil(new Date(2022, 12, 12));
        dummyData.setMasterKey(true);
        addKeyToAllKeys(dummyData);

        // Referencirati ovu metodu
        createCertificatesListView();

        // TODO [INTEGRACIJA] Dodati sve kljuceve u for-petlji --- Mozda ima addALL?

        // Referencirati metodu
        initializePublicKeyEncryptionKeys();

        // TODO [INTEGRACIJA] Za sve kljuceve KOJI SU PUBLIC (potrebna isMaster provera, a sta ako sifrujemo za neki drugi nas privatni kljuc? mozda ne treba provera). Treba napraviti Wrapper objekat i staviti false na sve!!!
        /**
         * Wrapper objekat je da bi checkbox radio!!!
         */
        // Ne treba ovaj deo, dodajemo sve u allKeys i onda on sve to iscitava
//        EncryptionWrapper ew = new EncryptionWrapper();
//        ew.setSelected(false);
//        ew.setElement(dummyData);
//        publicKeyEncryptionChoiceTableView.getItems().add(ew);


        // TODO [INTEGRACIJA] Tu treba popuniti takodje i ostale choiceBox-ove gde mozemo da biramo kljuceve
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
        String key = (String) exportKeyChoiceCombobox.getValue(); // konverzija u ExportedData

        if (key == null) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect key", "You have to specify the correct key!");
            return;
        }

        // TODO [INTEGRACIJA] Obavezno proveriti postojanost kljuca

        if (destination.length() == 0) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect filepath", "You have to specify the correct filepath!");
            return;
        }

        File outputFile = new File(destination);
        try (OutputStream os = new FileOutputStream(outputFile)) {
            outputFile.createNewFile();
            // TODO [INTEGRACIJA] Algoritam za export kljuca

        } catch (IOException e) {
            e.printStackTrace();
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
            // TODO [INTEGRACIJA] Ovde treba staviti logiku za unos privatnog kljuca, OBAVEZNO NA KRAJU TREBA AZURIRATI SVE KOMPONENTE {jos da skontam kako da napravim observera da to radi hahah}
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
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
            // TODO [INTEGRACIJA] Ovde treba staviti logiku za unos javnog kljuca, OBAVEZNO NA KRAJU TREBA AZURIRATI SVE KOMPONENTE {jos da skontam kako da napravim observera da to radi hahah}
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
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
        KeySizes rsaSize = parseRSAAlgorithmSelection(algorithm);
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

        // TODO [INTEGRACIJA] Izvrsavanje dodavanja novog kljuca -- OBAVEZNO AZURIRANJE KOMPONENTI
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
            // TODO [INTEGRACIJA] Obrada za export JAVNOG kljuca iz liste svih sertifikata na desni klik
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
                // TODO [INTEGRACIJA] Obrada za export TAJNOG kljuca iz liste svih sertifikata na desni klik, obavezno provera password-a
            }
        }
    }
}