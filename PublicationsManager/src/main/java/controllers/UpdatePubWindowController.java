package controllers;

import api.APIConnector;
import api.APIException;
import dataclasses.WEBCredentials;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.MultipleSelectionModel;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.layout.Pane;
import javafx.stage.Modality;
import javafx.stage.Stage;

import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UpdatePubWindowController {
    @FXML
    private Button publishButton;
    @FXML
    private Button addFileButton;
    @FXML
    private Button removeFileButton;
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

    private Stage myStage;
    private MainWindowController callback;
    private WEBCredentials credentials;

    private Map<String, String> allUserFiles;
    private String currentlySelectedFile;
    private List<String> attachedFilesIds;

    private String pid;

    public void init(Stage myStage, Map<String, String> files, WEBCredentials credentials, MainWindowController callback, Map<String, String> publication) {
        this.myStage = myStage;
        this.allUserFiles = files;
        this.credentials = credentials;
        this.callback = callback;
        this.attachedFilesIds = new ArrayList<String>();

        fillFields(publication);

        removeFileButton.setDisable(true);
    }

    private void fillFields(Map<String, String> publication) {
        pid = publication.get("id");
        titleField.setText(publication.get("title"));
        authorsField.setText(publication.get("authors"));
        yearField.setText(publication.get("year"));
        publisherField.setText(publication.get("publisher"));

        // Listing all attached files
        String stringFiles = publication.get("files");
        if (!stringFiles.equals("[]")) {
            String[] files = stringFiles.replaceAll("\\[", "")
                    .replaceAll("]", "")
                    .replaceAll("\\s", "")
                    .split(",");
            for (String fileID : files) {
                attachFile(fileID);
            }
        }
    }

    public void attachFile(String fid) {
        attachedFilesIds.add(fid);
        // Removing duplicates
        attachedFilesIds = new ArrayList<String>(
                new HashSet<String>(attachedFilesIds));
        refreshAttachedFileList();
    }

    @FXML
    public void detachFile() {
        String fid = null;
        Pattern pattern = Pattern.compile(".*\\(([^']*)\\).*");
        Matcher matcher = pattern.matcher(currentlySelectedFile);
        if (matcher.matches()) {
            fid = matcher.group(1);
        }

        if (fid != null) {
            attachedFilesIds.remove(fid);
            refreshAttachedFileList();
        } else {
            System.err.println("Cannot detach a file. File not selected.");
        }
    }

    private void refreshAttachedFileList() {
        ObservableList<String> items = FXCollections.observableArrayList();
        for (String id : attachedFilesIds) {
            items.add(allUserFiles.get(id) + " (" + id + ")");
        }
        fileListView.setItems(items);

        removeFileButton.setDisable(true);
    }

    @FXML
    public void selectFile() {
        currentlySelectedFile = null;

        MultipleSelectionModel model = fileListView.getSelectionModel();
        if (model == null) {
            return;
        }
        Object item = model.getSelectedItem();
        if (item == null) {
            return;
        }

        currentlySelectedFile = item.toString();

        removeFileButton.setDisable(false);
    }

    @FXML
    public void openFileAttachWindow() {
        FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/AddFileToPubWindow.fxml"));
        Stage newWindow = new Stage();
        try {
            newWindow.setScene(new Scene((Pane) loader.load()));
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        newWindow.setMinHeight(500);
        newWindow.setMinWidth(300);
        newWindow.setTitle("Choose a file to attach");
        newWindow.getIcons().add(new Image("/images/favicon.png"));
        newWindow.initModality(Modality.WINDOW_MODAL);
        newWindow.initOwner(myStage.getScene().getWindow());
        newWindow.show();

        // Pass data
        AddFileToPubWindowController controller = loader.getController();
        controller.init(newWindow, allUserFiles, this);
    }

    @FXML
    public void publish() {
        Map<String, String> publication = new HashMap<String, String>();
        publication.put("title", titleField.getText());
        publication.put("authors", authorsField.getText());
        publication.put("year", yearField.getText());
        publication.put("publisher", publisherField.getText());

        List<String> fileNamesWithIds = fileListView.getItems();
        List<String> fileIds = new ArrayList<String>();
        Pattern pattern = Pattern.compile(".*\\(([^']*)\\).*");
        for (String nameWithId : fileNamesWithIds) {
            Matcher matcher = pattern.matcher(nameWithId);
            if (matcher.matches()) {
                fileIds.add(matcher.group(1));
            }
        }
        publication.put("files", fileIds.toString());

        APIConnector connector = new APIConnector();
        int requestAttempts = 1;
        while (requestAttempts >= 0) {
            try {
                connector.updatePublication(credentials, publication, pid);
                callback.refreshPubList();
                myStage.close();
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
}
