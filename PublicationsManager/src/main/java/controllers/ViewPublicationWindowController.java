package controllers;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;

import java.util.Map;

public class ViewPublicationWindowController {
    @FXML
    private TextField titleField;
    @FXML
    private TextField authorsField;
    @FXML
    private TextField yearField;
    @FXML
    private TextField publisherField;
    @FXML
    private ListView fileListView;

    public void init(Map<String, String> publication){
        titleField.setText(publication.get("title"));
        authorsField.setText(publication.get("authors"));
        yearField.setText(publication.get("year"));
        publisherField.setText(publication.get("publisher"));

        // Listing all attached files
        String stringFiles = publication.get("files");
        String[] files = stringFiles.replaceAll("\\[", "").replaceAll("\\]", "").replaceAll("\\s", "").split(",");
        ObservableList<String> items = FXCollections.observableArrayList();
        items.addAll(files);
        fileListView.setItems(items);
    }
}
