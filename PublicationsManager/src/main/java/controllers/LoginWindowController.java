package controllers;

import api.APIConnector;
import api.APIException;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.Label;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import javafx.scene.Scene;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import dataclasses.WEBCredentials;
import javafx.scene.image.Image;

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

    @FXML
    public void handleOnKeyPressed(KeyEvent ke)
    {
        clearErrorMessage();

        // Handle Enter press
        if (ke.getCode().equals(KeyCode.ENTER))
        {
            login();
        }
    }

    @FXML
    public void login() {
        String token;
        try {
            APIConnector connector = new APIConnector();
            token = connector.fetchAuthToken(loginField.getText(), passwordField.getText());
        } catch (APIException e) {
            showErrorMessage(e.getMessage());
            return;
        }

        if (token != null) {
            try {
                FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/MainWindow.fxml"));
                Stage newWindow = new Stage();
                newWindow.setScene(new Scene((Pane) loader.load()));
                newWindow.setMinHeight(512);
                newWindow.setMinWidth(512);
                newWindow.setTitle("Main Window");
                newWindow.getIcons().add(new Image("/images/favicon.png"));
                newWindow.show();

                // Pass data
                WEBCredentials credentials = new WEBCredentials(loginField.getText(), passwordField.getText(), token);
                MainWindowController controller = loader.getController();
                controller.init(credentials);

                // Close login window
                Stage currStage = (Stage) loginButton.getScene().getWindow();
                currStage.close();
            } catch (IOException e) {
                // Error loading FXML
                e.printStackTrace();
                showErrorMessage("Internal app error.");
            }
        } else {
            showErrorMessage("Error fetching a token.");
        }
    }
}
