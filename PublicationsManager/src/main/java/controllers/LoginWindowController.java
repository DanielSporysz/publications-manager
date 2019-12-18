package controllers;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.stage.Stage;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;

import java.io.IOException;

public class LoginWindowController {
    @FXML
    private Button loginButton;
    private TextField loginField;
    private PasswordField passwordField;

    public void login() {
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
    }
}
