package controllers;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;

import java.util.ArrayList;
import java.util.List;
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

    public void init(Map<String, String> publication, Map<String, String> allFiles){
        titleField.setText(publication.get("title"));
        authorsField.setText(publication.get("authors"));
        yearField.setText(publication.get("year"));
        publisherField.setText(publication.get("publisher"));

        // Listing all attached files
        String stringFiles = publication.get("files");
        if(!stringFiles.equals("[]")) {
            String[] fileIDs = stringFiles.replaceAll("\\[", "").replaceAll("\\]", "").replaceAll("\\s", "").split(",");
            List<String> displayNames = new ArrayList<String>();
            for (String fid : fileIDs) {
                if (allFiles.get(fid) == null) {
                    displayNames.add("FILE HAS BEEN DELETED" + " (" + fid + ")");
                } else {
                    displayNames.add(allFiles.get(fid) + " (" + fid + ")");
                }
            }
            ObservableList<String> items = FXCollections.observableArrayList();
            items.addAll(displayNames);
            fileListView.setItems(items);
        }
    }
}
