package controllers;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.stage.Stage;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class LoginWindowController {
    @FXML
    private Button loginButton;
    private TextField loginField;
    private PasswordField passwordField;

    public void login() {
        boolean credentialsAreOk = false;
        try{
            credentialsAreOk = validateCredentials();
        } catch (IOException e){
            System.err.println("Error during the communication with a server.");
        }

        if (credentialsAreOk) {
            Parent root;
            try {
                Stage newWindow = new Stage();
                root = FXMLLoader.load(getClass().getClassLoader().getResource("fxml/MainWindow.fxml"));
                newWindow.setScene(new Scene(root));
                newWindow.setResizable(false);
                newWindow.setTitle("Log in");
                newWindow.show();

                // Close login window
                Stage currStage = (Stage) loginButton.getScene().getWindow();
                currStage.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.err.println("Credentials are incorrect.");
        }

    }

    private boolean validateCredentials() throws IOException {
        URL url = new URL("https://web.company.com/api/");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");



        return false;
    }
}
