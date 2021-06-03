package etf.openpgp.ts170124dss170372d.utility.helper;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.control.ButtonBar.ButtonData;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.PasswordField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;

/**
 * Ova cela klasa je preuzeta sa ovog <a href="https://gist.github.com/drguildo/ba2834bf52d624113041">linka</a>
 */
public class PasswordDialog extends Dialog<String> {
    private PasswordField passwordField;
    private String headerText;
    public PasswordDialog() {
        this("Please enter your password.");
    }
    public PasswordDialog(String headerText) {
        setTitle("Password");
        setHeaderText(headerText);

        ButtonType passwordButtonType = new ButtonType("Confirm input", ButtonData.OK_DONE);
        getDialogPane().getButtonTypes().addAll(passwordButtonType, ButtonType.CANCEL);

        passwordField = new PasswordField();
        passwordField.setPromptText("Password");

        HBox hBox = new HBox();
        hBox.getChildren().add(passwordField);
        hBox.setPadding(new Insets(20));

        HBox.setHgrow(passwordField, Priority.ALWAYS);

        getDialogPane().setContent(hBox);

        Platform.runLater(() -> passwordField.requestFocus());

        setResultConverter(dialogButton -> {
            if (dialogButton == passwordButtonType) {
                return passwordField.getText();
            }
            return null;
        });
    }

    public PasswordField getPasswordField() {
        return passwordField;
    }
}