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
import javafx.scene.control.MultipleSelectionModel;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
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
    private Button downloadButton;
    @FXML
    private Button deletePubButton;
    @FXML
    private Button editPubButton;

    private WEBCredentials credentials;
    private Map<String, String> files;
    private String currentlySelectedFileID;
    private String currentlySelectedPubID;
    private int reconnectAttempts = 0;

    private Stage myStage;

    public void init(WEBCredentials credentials, Stage stage) {
        this.credentials = credentials;
        this.myStage = stage;
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
        downloadButton.setDisable(true);
    }

    @FXML
    public void refreshPubList() {
        //TODO
    }

    @FXML
    public void selectFile(MouseEvent e) {
        currentlySelectedFileID = null;

        MultipleSelectionModel model = fileListView.getSelectionModel();
        if (model == null) {
            return;
        }
        Object item = model.getSelectedItem();
        if (item == null) {
            return;
        }

        //Extract file id from the text of ViewElement
        Pattern pattern = Pattern.compile(".*\\(([^']*)\\).*");
        Matcher matcher = pattern.matcher(item.toString());
        if (matcher.matches()) {
            currentlySelectedFileID = matcher.group(1);

            // After selecting a file, enable deletion button and download button
            deleteFileButton.setDisable(false);
            downloadButton.setDisable(false);
        }
    }

    @FXML
    public void uploadFile() {
        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showOpenDialog(myStage);
        uploadFile(selectedFile);
        refreshFileList();
    }

    private void uploadFile(File file) {
        if (file != null) {
            APIConnector connector = new APIConnector();
            try {
                connector.uploadFile(credentials, file);
            } catch (APIException outerEx) {
                if (outerEx.getMessage().equals("Incorrect credentials.")) {
                    try {
                        credentials.setUToken(connector.fetchAuthToken(credentials.getLogin(), credentials.getPassword()));
                        if (reconnectAttempts == 0) {
                            reconnectAttempts = 1;
                            uploadFile(file);
                            reconnectAttempts = 0;
                        }
                    } catch (APIException innerEx) {
                        System.err.println("Error uploading a file.");
                    }
                } else {
                    System.err.println("Error uploading a file.");
                }
            }
        }
    }

    @FXML
    public void downloadFile() {
        //TODO
    }

    @FXML
    public void deleteFile() {
        if (currentlySelectedFileID != null) {
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
