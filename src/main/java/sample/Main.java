package sample;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

public class Main extends Application {
    // Sluzi da mozemo da otvorimo file explorer u controlleru, zahteva stage
    static Main mainReference;
    // TODO [INTEGRACIJA] static KeyManager keyManagerReference;
    Stage currentStage;

    @Override
    public void start(Stage primaryStage) throws Exception{
        currentStage = primaryStage;
        Parent root = FXMLLoader.load(getClass().getClassLoader().getResource("sample.fxml"));
        primaryStage.setTitle("PGP");
        primaryStage.setScene(new Scene(root));
        primaryStage.getIcons().add(new Image("logo.png"));
        primaryStage.setResizable(false);
        mainReference = this;
        primaryStage.show();

    }

    @Override
    public void stop() {
        // TODO [INTEGRACIJA] keyManagerReference.saveKeys();
    }

    public static void main(String[] args) {

        launch(args);
    }
}
