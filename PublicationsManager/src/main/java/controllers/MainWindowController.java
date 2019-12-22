package controllers;

import api.APIConnector;
import api.APIException;
import dataclasses.WEBCredentials;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.Label;
import javafx.scene.input.MouseEvent;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainWindowController {
    @FXML
    private ListView fileListView;
    @FXML
    private ListView pubListView;
    @FXML
    private Label topGreeting;
    @FXML
    private Button deleteFileButton;
    @FXML
    private Button deletePubButton;
    @FXML
    private Button editPubButton;

    private WEBCredentials credentials;
    private Map<String, String> files;
    private String currentlySelectedFileID;
    private String currentlySelectedPubID;

    public void init(WEBCredentials credentials) {
        this.credentials = credentials;
        topGreeting.setText("Welcome " + credentials.getLogin() + "!");
        refreshFileList();
        refreshPubList();
    }

    @FXML
    public void refreshFileList() {
        APIConnector connector = new APIConnector();
        try {
            files = connector.fetchFileList(credentials);
        } catch (APIException e) {
            try {
                if (e.getMessage().equals("Incorrect credentials.")) { // Fetch a new auth_token and try again
                    credentials.setUToken(connector.fetchAuthToken(credentials.getLogin(), credentials.getPassword()));
                    refreshFileList();
                } else {
                    e.printStackTrace();
                }
                return;
            } catch (APIException ex) {
                ex.printStackTrace();
                return;
            }
        }

        ObservableList<String> items = FXCollections.observableArrayList();
        for (Map.Entry<String, String> entry : files.entrySet()) {
            items.add(entry.getValue() + "\t(" + entry.getKey() + ")");
        }
        fileListView.setItems(items);
    }

    @FXML
    public void refreshPubList() {
        //TODO
    }

    @FXML
    public void selectFile(MouseEvent e) {
        // After selecting a file, enable deletion button
        deleteFileButton.setDisable(false);

        //Extract file id from the text of ViewElement
        Pattern pattern = Pattern.compile(".*\\(([^']*)\\).*");
        Matcher matcher = pattern.matcher(fileListView.getSelectionModel().getSelectedItem().toString());
        if(matcher.matches()) {
            currentlySelectedFileID = matcher.group(1);
        } else {
            currentlySelectedFileID = null;
        }
    }

}
