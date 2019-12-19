package controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import jdk.nashorn.internal.ir.ObjectNode;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import dataclasses.WEBCredentials;

import java.io.IOException;
import java.nio.charset.MalformedInputException;
import java.util.Map;

public class LoginWindowController {
    @FXML
    private Button loginButton;
    @FXML
    private TextField loginField;
    @FXML
    private PasswordField passwordField;

    private final String url = "https://web.company.com/api";

    public void login() {
        String token = fetchToken();

        if (token != null) {
            try {
                FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/MainWindow.fxml"));
                Stage newWindow = new Stage();
                newWindow.setScene(new Scene((Pane)loader.load()));
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
                e.printStackTrace();
            }
        } else {
            System.err.println("Credentials are incorrect.");
        }

    }

    private String fetchToken() {
        try {
            Connection.Response response =
                    Jsoup.connect(url + "/utoken")
                            .userAgent("Mozilla/5.0")
                            .timeout(10 * 1000)
                            .method(Connection.Method.GET)
                            .data("login", "YOUR_LOGINID")
                            .data("txtloginpassword", "YOUR_PASSWORD")
                            .followRedirects(true)
                            .ignoreContentType(true)
                            .execute();

            if (response.statusCode() == 201) {
                ObjectMapper mapper = new ObjectMapper();
                String json = response.body();
                Map<String, String> map = mapper.readValue(json, Map.class);
                return map.get("auth_token");
            } else {
                // incorrect credentials probably
                return null;
            }
        } catch (IOException ioe) {
            // Server error, response error
            System.out.println("Exception: " + ioe);
        }
        return null;
    }
}
