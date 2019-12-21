package controllers;

import api.APIConnector;
import com.fasterxml.jackson.databind.ObjectMapper;
import api.APIException;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.Label;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import javafx.scene.Scene;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import dataclasses.WEBCredentials;

import java.io.IOException;

public class LoginWindowController {
    @FXML
    private Button loginButton;
    @FXML
    private TextField loginField;
    @FXML
    private PasswordField passwordField;
    @FXML
    private Label errorLabel;

    public void clearErrorMessage() {
        errorLabel.setText("");
    }

    private void showErrorMessage(String message) {
        errorLabel.setText(message);
    }

    public void login() {
        String token;
        try {
            APIConnector connector = new APIConnector();
            token = connector.fetchToken(loginField.getText(), passwordField.getText());
        } catch (APIException e) {
            showErrorMessage(e.getMessage());
            return;
        }

        if (token != null) {
            try {
                FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/MainWindow.fxml"));
                Stage newWindow = new Stage();
                newWindow.setScene(new Scene((Pane) loader.load()));
                newWindow.setResizable(false);
                newWindow.setTitle("Main Window");
                newWindow.show();
                MainWindowController controller = loader.getController();
                WEBCredentials credentials = new WEBCredentials(loginField.getText(), passwordField.getText(), token);
                controller.init(credentials);

                // Close login window
                Stage currStage = (Stage) loginButton.getScene().getWindow();
                currStage.close();
            } catch (IOException e) {
                // Error loading FXML
                showErrorMessage("Internal app error.");
            }
        } else {
            showErrorMessage("Error fetching a token.");
        }
    }

}
