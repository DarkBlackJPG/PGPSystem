package sample;

import javafx.collections.FXCollections;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Glavni kontroler za FX view
 */
public class Controller {
    private List<String> algorithms = new ArrayList<>();
    {
        algorithms.add("Triple DES");
        algorithms.add("IDEA");
    }

    // Begin - Encryption
    public TextField browseFileLocationTextField;
    public CheckBox useEncryptionCheckBox;
    public ChoiceBox encryptionAlgorithmsChoiceBox;
    public CheckBox signCheckBox;
    public ChoiceBox signChoiceBox;
    public CheckBox compressionCheckBox;
    public CheckBox base64ConversionCheckBox;
    public Button sendButton;
    public Button browseFileChooserTriggerButton;

    /**
     * Koristi se za pretragu fajla koji zelimo da kriptujemo. Otvara prozor i upisuje u textpox putanju.
     * @param actionEvent
     */
    public void browseFiileAction(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        File encryptFile = fileChooser.showOpenDialog(Main.mainReference.currentStage);
        if(encryptFile != null) {
            browseFileLocationTextField.setText(encryptFile.getAbsolutePath());
        }
    }

    public void sendAction(ActionEvent actionEvent) {
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
        encryptionAlgorithmsChoiceBox.setItems(FXCollections.observableList(algorithms));
    }

}
