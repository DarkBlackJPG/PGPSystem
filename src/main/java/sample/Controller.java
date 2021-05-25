package sample;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.FileChooser;

import java.io.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Glavni kontroler za FX view
 */

// ----------|
// PRIVREMENO|
// ----------|


public class Controller {
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
    public ComboBox exportKeyChoiceCombobox;
    public Button browseImportSecretKeyButton;
    public TextField pathToImportKeyFileTextField;
    public Button executeImportSecretKeyButton;
    public Button browseImportPublicKeyButton;
    public Button executeImportPublicKeyButton;
    public TextField publicKeyFIleLocationTextField;
    public TableView certificateTableTableView;
    public TextField newKeyPairName;
    public TextField newKeyPairEmail;
    public PasswordField newKeyPairPassword;
    public ComboBox newKeyPairAlgorithm;
    public Button generateNewKeyPairButton;
    public TextField browseFileLocationTextField;
    public CheckBox useEncryptionCheckBox;
    public ChoiceBox encryptionAlgorithmsChoiceBox;
    public CheckBox signCheckBox;
    public ChoiceBox signChoiceBox;
    public CheckBox compressionCheckBox;
    public CheckBox base64ConversionCheckBox;
    public Button sendButton;
    public Button browseFileChooserTriggerButton;
    private List<String> symmetricAlgorithms = new ArrayList<>();
    private List<String> asymmetricAlgorithms = new ArrayList<>();
    private ObservableList<ExportedKeyData> keys = FXCollections.observableArrayList();

    {
        symmetricAlgorithms.add("Triple DES");
        symmetricAlgorithms.add("IDEA");

        asymmetricAlgorithms.add("RSA 1024");
        asymmetricAlgorithms.add("RSA 2048");
        asymmetricAlgorithms.add("RSA 4096");
    }


    private void showErrorDialog(String title, String header, String text) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(title);
        alert.setHeaderText(header);
        alert.setContentText(text);
        alert.showAndWait();
    }

    /**
     * Koristi se za pretragu fajla koji zelimo da kriptujemo. Otvara prozor i upisuje u textpox putanju.
     */
//    public void browseFiileAction(ActionEvent actionEvent) {
//        FileChooser fileChooser = new FileChooser();
//        File encryptFile = fileChooser.showOpenDialog(Main.mainReference.currentStage);
//        if(encryptFile != null) {
//            browseFileLocationTextField.setText(encryptFile.getAbsolutePath());
//        }
//    }
    private boolean checkFilePath(String filePath) {
        String regularExpression = "([a-zA-Z]:)?(\\[a-zA-Z0-9_-]+)+\\?";
        Pattern pattern = Pattern.compile(regularExpression);
        Matcher matcher = pattern.matcher(filePath);
        return matcher.matches();
    }

    public void sendAction(ActionEvent actionEvent) {
        String fileLocation = browseFileLocationTextField.getText();
        if (fileLocation.length() == 0 || !checkFilePath(fileLocation)) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect filepath", "You have to specify a correct filepath!");
            return;
        }
        File file = new File(fileLocation);
        if (!file.exists()) {
            showErrorDialog("Input parameters are incorrrect!", "File doesn't exist!", "The file with the provided filepath doesn't exist!");
            return;
        }
        // -- Ovo treba prosiriti tako da mozemo vise ljudi da odabermeo
        boolean useEncryption = useEncryptionCheckBox.isSelected();
        String encryptionAlgorithm = (String) encryptionAlgorithmsChoiceBox.getValue();
        //
        boolean sign = signCheckBox.isSelected();
        boolean useCompression = compressionCheckBox.isSelected();
        boolean base64 = base64ConversionCheckBox.isSelected();
        String signature = (String) signChoiceBox.getValue();

        if (sign && signature == null) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect signature", "You have to specify for the signature!");
            return;
        }
        // Slicno za enkripciju

        // Algorithm

    }

    /**
     * Promenimo stanje ChoiceBox-a na disabled ako je odcekirano (za use encryption)
     * @param actionEvent
     */
    public void useEncryptionChangeAction(ActionEvent actionEvent) {
        encryptionAlgorithmsChoiceBox.setDisable(!useEncryptionCheckBox.isSelected());
    }

    /**
     * Promenimo stanje ChoiceBox-a na disabled ako je odcekirano ( za sign)
     * @param actionEvent
     */
    public void signChangeAction(ActionEvent actionEvent) {
        signChoiceBox.setDisable(!signCheckBox.isSelected());
    }

    public void compressionChangeAction(ActionEvent actionEvent) {
    }

    public void base64ConversionChangeAction(ActionEvent actionEvent) {
    }

    // End - Encryption


    /**
     * Inicijalizovanje pogleda, menjati po potrebi
     */
    @FXML
    void initialize() {
        // Ubacujemo algoritme koje nudomo
        encryptionAlgorithmsChoiceBox.setItems(FXCollections.observableList(symmetricAlgorithms));
        newKeyPairAlgorithm.setItems(FXCollections.observableList(asymmetricAlgorithms));

        ExportedKeyData dummyData = new ExportedKeyData();
        dummyData.setEmail("stefant@98.com");
        dummyData.setUserName("Stefan Teslic");
        dummyData.setKeyID(123123123);
        dummyData.setValidFrom(new Date());
        dummyData.setValidUntil(new Date(2022, 12, 12));
        keys.add(dummyData);

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
        certificateTableTableView.getItems().add(dummyData);

    }

    public void browseFiileAction(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Resource File");
        File file = fileChooser.showOpenDialog(Main.mainReference.currentStage);
        if (file != null) {
            browseFileLocationTextField.setText(file.getAbsolutePath());
        }
    }


    public void startDecriptionAndVerificationButton(ActionEvent actionEvent) {
        String fileToDecrypt = browseDecryptionFileLocationTextField.getText();
        File file = new File(fileToDecrypt);
        if (!file.exists()) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect filepath", "You have to specify the correct file path and/or the file doesn't exist!");
            return;
        }
        try {
            InputStream stream = new FileInputStream(file);
            // algoritma

            // displayDecriptionAndVerificationOutputTextField.setText ssa rezultatom
            // Eventualno dialog box sa info da li je uspeo da verifikuje

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public void chooseDecryptionFileLocation(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Resource File");
        File file = fileChooser.showOpenDialog(Main.mainReference.currentStage);
        if (file != null) {
            decryptionFileLocationTextField.setText(file.getAbsolutePath());
        }
    }

    public void saveDecryptedFIle(ActionEvent actionEvent) {
        String fileLocation = decryptionFileLocationTextField.getText();
        if (fileLocation.length() == 0) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect filepath", "You have to specify the correct file path!");
            return;
        }
        File newFile = new File(fileLocation);
        OutputStream os;
        try {
            newFile.createNewFile();
            os = new FileOutputStream(newFile);
            // algoritam

        } catch (IOException e) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect filepath", "You have to specify the correct file path!");
        } finally {
            // Kako zatvoriti stream??
        }
    }

    public void chooseExportKeysFileLocation(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Resource File");
        File file = fileChooser.showOpenDialog(Main.mainReference.currentStage);
        if (file != null) {
            exportFileLocationTextField.setText(file.getAbsolutePath());
        }
    }

    public void executeExportKey(ActionEvent actionEvent) {
        String destination = exportFileLocationTextField.getText();
        String key = (String) exportKeyChoiceCombobox.getValue(); // konverzija u ExportedData

        if (key == null) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect key", "You have to specify the correct key!");
            return;
        }

//        TODO if (key exists in keychain)
        if (destination.length() == 0) {
            showErrorDialog("Input parameters are incorrrect!", "Incorrect filepath", "You have to specify the correct filepath!");
            return;
        }

        File outputFile = new File(destination);
        try {
            outputFile.createNewFile();
            OutputStream os = new FileOutputStream(outputFile);

            // Algorithm

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            // Zatvaranje output stream
        }
    }

    public void keyChoiceComboboxAction(ActionEvent actionEvent) {
    }

    public void browseImportSecretKey(ActionEvent actionEvent) {
    }

    public void executeImportSecretKey(ActionEvent actionEvent) {
    }

    public void browseImportPublicKey(ActionEvent actionEvent) {
    }

    public void executeImportPublicKey(ActionEvent actionEvent) {
    }


    private boolean checkMail(String mail) {
        String regex = "^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(mail);
        return matcher.matches();
    }

    public void generateNewKeyPairButton(ActionEvent actionEvent) {
        String name = newKeyPairName.getText();
        String email = newKeyPairEmail.getText();
        String password = newKeyPairPassword.getText();
        String algorithm = (String) newKeyPairAlgorithm.getValue();
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

        // OK
        // Generisanje

    }

    public void browseDecryptionFIleAction(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Resource File");
        File file = fileChooser.showOpenDialog(Main.mainReference.currentStage);
        if (file != null) {
            browseDecryptionFileLocationTextField.setText(file.getAbsolutePath());
        }
    }

    public void contextMenuExportKey(ActionEvent actionEvent) {
        ExportedKeyData keyData = (ExportedKeyData) certificateTableTableView.getSelectionModel().getSelectedItem();
        if (keyData != null) {
            // Obrada
        }
    }

    public void contextMenuDeleteKey(ActionEvent actionEvent) {
        ExportedKeyData keyData = (ExportedKeyData) certificateTableTableView.getSelectionModel().getSelectedItem();
        if (keyData != null) {
            // Obrada
        }
    }

    public void contextMenuBackupKey(ActionEvent actionEvent) {
        ExportedKeyData keyData = (ExportedKeyData) certificateTableTableView.getSelectionModel().getSelectedItem();
        if (keyData != null) {
            if (!keyData.getIsMasterKey()) {
                showErrorDialog("Incorrect key selection!", "Cannot backup public key!", "You cant invoke master key backup on public keys!");
                return;
            } else {
                // obrada
            }
        }
    }
}
