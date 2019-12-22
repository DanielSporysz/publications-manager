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
    private int reconnectAttempts = 0;

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
        } catch (APIException outerEx) {
            // Fetch a new auth_token and try again
            if (outerEx.getMessage().equals("Incorrect credentials.")) {
                try {
                    credentials.setUToken(connector.fetchAuthToken(credentials.getLogin(), credentials.getPassword()));
                    if (reconnectAttempts == 0) {
                        reconnectAttempts = 1;
                        refreshFileList();
                        reconnectAttempts = 0;
                    }
                } catch (APIException innerEx) {
                    System.err.println("Error fetching a list of files.");
                    return;
                }
            } else {
                System.err.println("Error fetching a list of files.");
                return;
            }
        }

        ObservableList<String> items = FXCollections.observableArrayList();
        for (Map.Entry<String, String> entry : files.entrySet()) {
            items.add(entry.getValue() + " (" + entry.getKey() + ")");
        }
        fileListView.setItems(items);

        // Force user to click on a file from a list before using delete option
        deleteFileButton.setDisable(true);
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
        if (matcher.matches()) {
            currentlySelectedFileID = matcher.group(1);
        } else {
            currentlySelectedFileID = null;
        }
    }

    @FXML
    public void uploadFile(){

    }

    @FXML
    public void deleteFile(){
        if (currentlySelectedFileID != null){
            APIConnector connector = new APIConnector();
            try {
                connector.deleteFile(credentials, currentlySelectedFileID);
            } catch (APIException outerEx) {
                if (outerEx.getMessage().equals("Incorrect credentials.")) {
                    try {
                        credentials.setUToken(connector.fetchAuthToken(credentials.getLogin(), credentials.getPassword()));
                        if (reconnectAttempts == 0) {
                            reconnectAttempts = 1;
                            deleteFile();
                            reconnectAttempts = 0;
                        }
                    } catch (APIException innerEx) {
                        System.err.println("Error fetching a list of files.");
                        return;
                    }
                } else {
                    System.err.println("Error fetching a list of files.");
                    return;
                }
            }
        }
        refreshFileList();
    }

}
