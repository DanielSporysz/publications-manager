package controllers;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.stage.Stage;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.io.IOException;
import java.util.Map;

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
        try{

            Connection.Response response =
                    Jsoup.connect("https://web.company.com/api/utoken")
                            .userAgent("Mozilla/5.0")
                            .timeout(10 * 1000)
                            .method(Connection.Method.GET)
                            .data("txtloginid", "YOUR_LOGINID")
                            .data("txtloginpassword", "YOUR_PASSWORD")
                            .data("random", "123342343")
                            .data("task", "login")
                            .data("destination", "/welcome")
                            .followRedirects(true)
                            .execute();

            //parse the document from response
            Document document = response.parse();

            //get cookies
            Map<String, String> mapCookies = response.cookies();

            System.out.println(mapCookies);

        }catch(IOException ioe){
            System.out.println("Exception: " + ioe);
        }
        //TODO DISABLE SSL CERTIFICATE CHECKING
        return false;
    }
}
