import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

public class Main extends Application {
    @Override
    public void start(Stage primaryStage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("fxml/LoginWindow.fxml"));
        primaryStage.setScene(new Scene(root));
        primaryStage.setResizable(false);
        primaryStage.setTitle("Publications Manager");
        primaryStage.getIcons().add(new Image("/images/favicon.png"));
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }

    // Example of a pop up window blocking the paren window
//    private void showLoginWindow(Stage primaryStage) throws IOException {
//        Parent root = FXMLLoader.load(getClass().getResource("fxml/LoginWindow.fxml"));
//        Stage newWindow = new Stage();
//
//        newWindow.setTitle("Log in");
//        newWindow.setScene(new Scene(root));
//        newWindow.initModality(Modality.WINDOW_MODAL);
//        newWindow.initOwner(primaryStage);
//
//        newWindow.show();
//    }
}
