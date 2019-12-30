package controllers;

import api.APIConnector;
import api.APIException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dataclasses.WEBCredentials;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.Pane;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
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
    @FXML
    private Button viewPubButton;

    private WEBCredentials credentials;
    private Map<String, String> files;
    private Map<String, String> publications;
    private String currentlySelectedFileID;
    private String currentlySelectedPub;

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

    private boolean askForConfirmation(String question) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION, question, ButtonType.NO, ButtonType.YES);
        Stage stage = (Stage) alert.getDialogPane().getScene().getWindow();
        stage.getIcons().add(new Image("/images/favicon.png"));

        //Deactivate Defaultbehavior for yes-Button:
        Button yesButton = (Button) alert.getDialogPane().lookupButton(ButtonType.YES);
        yesButton.setDefaultButton(false);
        //Activate Defaultbehavior for no-Button:
        Button noButton = (Button) alert.getDialogPane().lookupButton(ButtonType.NO);
        noButton.setDefaultButton(true);

        alert.showAndWait();
        if (alert.getResult() == ButtonType.YES) {
            return true;
        } else {
            return false;
        }
    }

    @FXML
    public void deleteFile() {
        if (currentlySelectedFileID != null) {
            boolean deleteFile = askForConfirmation("Delete " + currentlySelectedFileID + " ?");
            if (!deleteFile) {
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
        publications = null;
        APIConnector connector = new APIConnector();
        int requestAttempts = 1;
        while (requestAttempts >= 0) {
            try {
                publications = connector.fetchPubList(credentials);
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
        if (publications != null) {
            ObjectMapper mapper = new ObjectMapper();
            for (Map.Entry<String, String> entry : publications.entrySet()) {
                String json = entry.getValue();
                try {
                    Map<String, String> map = mapper.readValue(json, Map.class);
                    items.add(map.get("title") + " (" + entry.getKey() + ")");
                } catch (JsonProcessingException e) {
                    System.err.println("Could not extract publication title. The pub list is missing elements.");
                }
            }
        }
        pubListView.setItems(items);

        // Force user to click on a file from the list before using any options
        deletePubButton.setDisable(true);
        editPubButton.setDisable(true);
        viewPubButton.setDisable(true);
    }

    @FXML
    public void openPublicationCreationWindow() {
        FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/NewPublicationWindow.fxml"));
        Stage newWindow = new Stage();
        try {
            newWindow.setScene(new Scene((Pane) loader.load()));
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        newWindow.setMinHeight(400);
        newWindow.setMinWidth(512);
        newWindow.setTitle("Creating a new publication");
        newWindow.getIcons().add(new Image("/images/favicon.png"));
        newWindow.initModality(Modality.WINDOW_MODAL);
        newWindow.initOwner(myStage.getScene().getWindow());
        newWindow.show();

        // Pass data
        NewPublicationWindowController controller = loader.getController();
        controller.init(newWindow, files, credentials, this);
    }

    @FXML
    public void selectPublication(MouseEvent e) {
        currentlySelectedPub = null;

        MultipleSelectionModel model = pubListView.getSelectionModel();
        if (model == null) {
            return;
        }
        Object item = model.getSelectedItem();
        if (item == null) {
            return;
        }

        currentlySelectedPub = item.toString();

        deletePubButton.setDisable(false);
        editPubButton.setDisable(false);
        viewPubButton.setDisable(false);
    }

    @FXML
    public void deletePub(MouseEvent event) {
        if (currentlySelectedPub == null) {
            System.err.println("Cannot delete a pub. No pubId selected.");
            return;
        }

        String pid = extractID(currentlySelectedPub);
        if (pid == null) {
            System.err.println("Couldn't extract pub Id.");
            return;
        }

        boolean deletePub = askForConfirmation("Delete " + pid + " ?");
        if (!deletePub) {
            return;
        }

        APIConnector connector = new APIConnector();
        int requestAttempts = 1;
        while (requestAttempts >= 0) {
            try {
                connector.deletePub(credentials, pid);
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

        refreshPubList();
    }

    private Map<String, String> currentPubAsMap() {
        if (currentlySelectedPub == null) {
            System.err.println("currentPubAsMap: no pub is selected");
            return null;
        }
        String pid = extractID(currentlySelectedPub);
        if (pid == null) {
            System.err.println("currentPubAsMap: couldn't extract pub ID");
            return null;
        }

        String stringPublication = publications.get(pid);
        Map<String, String> publication = null;
        try {
            ObjectMapper mapper = new ObjectMapper();
            publication = mapper.readValue(stringPublication, Map.class);
            return publication;
        } catch (JsonProcessingException e) {
            System.err.println("currentPubAsMap: could not map publication");
            return null;
        }
    }

    @FXML
    public void editPub() {
        Map<String, String> publication = currentPubAsMap();
        if (publication == null) {
            return;
        }

        FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/UpdatePubWindow.fxml"));
        Stage newWindow = new Stage();
        try {
            newWindow.setScene(new Scene((Pane) loader.load()));
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        newWindow.setMinHeight(500);
        newWindow.setMinWidth(300);
        newWindow.setTitle("Publication Edition");
        newWindow.getIcons().add(new Image("/images/favicon.png"));
        newWindow.initModality(Modality.WINDOW_MODAL);
        newWindow.initOwner(myStage.getScene().getWindow());
        newWindow.show();

        // Pass data
        UpdatePubWindowController controller = loader.getController();
        controller.init(newWindow, files, credentials, this, publication);
    }

    @FXML
    public void viewPub() {
        Map<String, String> publication = currentPubAsMap();
        if (publication == null) {
            return;
        }

        FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/ViewPublicationWindow.fxml"));
        Stage newWindow = new Stage();
        try {
            newWindow.setScene(new Scene((Pane) loader.load()));
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        newWindow.setMinHeight(500);
        newWindow.setMinWidth(300);
        newWindow.setTitle("Publication");
        newWindow.getIcons().add(new Image("/images/favicon.png"));
        newWindow.initModality(Modality.WINDOW_MODAL);
        newWindow.initOwner(myStage.getScene().getWindow());
        newWindow.show();

        // Pass data
        ViewPublicationWindowController controller = loader.getController();
        controller.init(publication, files);
    }

    private String extractID(String text) {
        Pattern pattern = Pattern.compile(".*\\(([^']*)\\).*");
        Matcher matcher = pattern.matcher(text);
        if (matcher.matches()) {
            return matcher.group(1);
        } else {
            return null;
        }
    }

    @FXML
    public void logout() {
        try {
            Stage stage = new Stage();
            FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/LoginWindow.fxml"));
            stage.setScene(new Scene((Pane) loader.load()));
            stage.setResizable(false);
            stage.setTitle("Publications Manager");
            stage.getIcons().add(new Image("/images/favicon.png"));
            stage.show();

            //Request focus on login
            LoginWindowController controller = loader.getController();
            controller.requestFocusOnLoginField();

            myStage.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
