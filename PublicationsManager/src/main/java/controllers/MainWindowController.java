package controllers;

import api.APIConnector;
import api.APIException;
import dataclasses.WEBCredentials;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;
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
        files = null;
        APIConnector connector = new APIConnector();
        int requestAttempts = 1;
        while (requestAttempts >= 0) {
            try {
                files = connector.fetchFileList(credentials);
                break;
            } catch (APIException e) {
                //e.printStackTrace();
                requestAttempts--;
                try {
                    credentials.setUToken(connector.fetchAuthToken(credentials.getLogin(), credentials.getPassword()));
                } catch (APIException ex) {
                    ex.printStackTrace();
                    break;
                }
            }
        }

        // Add the file list to the view
        ObservableList<String> items = FXCollections.observableArrayList();
        if (files != null) {
            for (Map.Entry<String, String> entry : files.entrySet()) {
                items.add(entry.getValue() + " (" + entry.getKey() + ")");
            }
        }
        fileListView.setItems(items);

        // Force user to click on a file from the list before using any options
        deleteFileButton.setDisable(true);
        downloadButton.setDisable(true);
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
        File file = fileChooser.showOpenDialog(myStage);
        if (file == null) {
            return;
        }

        APIConnector connector = new APIConnector();
        int requestAttempts = 1;
        while (requestAttempts >= 0) {
            try {
                connector.uploadFile(credentials, file);
                break;
            } catch (APIException e) {
                //e.printStackTrace();
                requestAttempts--;
                try {
                    credentials.setUToken(connector.fetchAuthToken(credentials.getLogin(), credentials.getPassword()));
                } catch (APIException ex) {
                    ex.printStackTrace();
                    break;
                }
            }
        }

        refreshFileList();
    }

    @FXML
    public void downloadFile() {
        FileChooser fileChooser = new FileChooser();
        File file = fileChooser.showSaveDialog(myStage);
        if (file == null) {
            return;
        }

        APIConnector connector = new APIConnector();
        int requestAttempts = 1;
        while (requestAttempts >= 0) {
            try {
                BufferedInputStream inputStream = connector.downloadFile(credentials, currentlySelectedFileID);
                try {
                    FileOutputStream fos = new FileOutputStream(file);
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = inputStream.read(buffer)) != -1) {
                        fos.write(buffer, 0, len);
                    }
                    inputStream.close();
                    fos.close();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                break;
            } catch (APIException e) {
                //e.printStackTrace();
                requestAttempts--;
                try {
                    credentials.setUToken(connector.fetchAuthToken(credentials.getLogin(), credentials.getPassword()));
                } catch (APIException ex) {
                    ex.printStackTrace();
                    break;
                }
            }
        }
    }

    @FXML
    public void deleteFile() {
        if (currentlySelectedFileID != null) {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION, "Delete " + currentlySelectedFileID + " ?", ButtonType.NO, ButtonType.YES);
            Stage stage = (Stage) alert.getDialogPane().getScene().getWindow();
            stage.getIcons().add(new Image("/images/favicon.png"));

            //Deactivate Defaultbehavior for yes-Button:
            Button yesButton = (Button) alert.getDialogPane().lookupButton( ButtonType.YES );
            yesButton.setDefaultButton( false );
            //Activate Defaultbehavior for no-Button:
            Button noButton = (Button) alert.getDialogPane().lookupButton( ButtonType.NO );
            noButton.setDefaultButton( true );

            alert.showAndWait();
            if (alert.getResult() != ButtonType.YES) {
                return;
            }

            APIConnector connector = new APIConnector();
            int requestAttempts = 1;
            while (requestAttempts >= 0) {
                try {
                    connector.deleteFile(credentials, currentlySelectedFileID);
                    break;
                } catch (APIException e) {
                    //e.printStackTrace();
                    requestAttempts--;
                    try {
                        credentials.setUToken(connector.fetchAuthToken(credentials.getLogin(), credentials.getPassword()));
                    } catch (APIException ex) {
                        ex.printStackTrace();
                        break;
                    }
                }
            }
        }

        refreshFileList();
    }

    @FXML
    public void refreshPubList() {
        //TODO

        deletePubButton.setDisable(true);
        editPubButton.setDisable(true);
    }

}
