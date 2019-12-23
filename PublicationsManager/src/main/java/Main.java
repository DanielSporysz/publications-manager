import controllers.LoginWindowController;
import controllers.MainWindowController;
import javafx.application.Application;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/LoginWindow.fxml"));
        primaryStage.setScene(new Scene((Pane) loader.load()));
        primaryStage.setResizable(false);
        primaryStage.setTitle("Publications Manager");
        primaryStage.getIcons().add(new Image("/images/favicon.png"));
        primaryStage.show();

        //Request focus on login
        LoginWindowController controller = loader.getController();
        controller.requestFocusOnLoginField();
    }

    public static void main(String[] args) {
        launch(args);
    }

}
