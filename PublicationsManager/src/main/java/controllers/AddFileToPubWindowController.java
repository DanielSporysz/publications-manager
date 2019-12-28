package controllers;

import com.fasterxml.jackson.core.util.VersionUtil;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.MultipleSelectionModel;
import javafx.stage.Stage;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AddFileToPubWindowController {

    @FXML
    private ListView fileListView;
    @FXML
    private Button attachFileButton;

    private Stage myStage;
    private NewPublicationWindowController callback;
    private Map<String, String> files;
    private String currentlySelectedFileWithID;

    public void init(Stage myStage, Map<String, String> files, NewPublicationWindowController callback) {
        this.myStage = myStage;
        this.files = files;
        this.callback = callback;

        fillFileListView();
    }

    private void fillFileListView() {
        // Add the file list to the view
        ObservableList<String> items = FXCollections.observableArrayList();
        if (files != null) {
            for (Map.Entry<String, String> entry : files.entrySet()) {
                items.add(entry.getValue() + " (" + entry.getKey() + ")");
            }
        }
        fileListView.setItems(items);

        attachFileButton.setDisable(true);
    }

    @FXML
    public void selectFile() {
        currentlySelectedFileWithID = null;

        MultipleSelectionModel model = fileListView.getSelectionModel();
        if (model == null) {
            return;
        }
        Object item = model.getSelectedItem();
        if (item == null) {
            return;
        }

        currentlySelectedFileWithID = item.toString();

        attachFileButton.setDisable(false);
    }

    @FXML
    public void attachFile() {
        String fid = null;
        Pattern pattern = Pattern.compile(".*\\(([^']*)\\).*");
        Matcher matcher = pattern.matcher(currentlySelectedFileWithID);
        if (matcher.matches()) {
            fid = matcher.group(1);
        }

        if (fid != null) {
            callback.attachFile(fid);
            myStage.close();
        } else {
            System.err.println("File to attach has not been selected yet.");
        }
    }

}
