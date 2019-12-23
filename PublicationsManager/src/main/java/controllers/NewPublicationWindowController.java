package controllers;

import api.APIConnector;
import api.APIException;
import dataclasses.WEBCredentials;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.MultipleSelectionModel;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NewPublicationWindowController {
    @FXML
    private Button addPubButton;
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
    private Map<String, String> files;
    private WEBCredentials credentials;

    public void init(Stage myStage, Map<String, String> files, WEBCredentials credentials, MainWindowController callback){
        this.myStage = myStage;
        this.files = files;
        this.credentials = credentials;
        this.callback = callback;
    }

    @FXML
    public void publish(){
        Map<String, String> publication = new HashMap<String, String>();
        publication.put("title", titleField.getText());
        publication.put("authors", authorsField.getText());
        publication.put("year", yearField.getText());
        publication.put("publisher", publisherField.getText());

        List<String> fileNamesWithIds = fileListView.getItems();
        List<String> fileIds = new ArrayList<String>();
        Pattern pattern = Pattern.compile(".*\\(([^']*)\\).*");
        for (String nameWithId : fileNamesWithIds){
            Matcher matcher = pattern.matcher(nameWithId);
            if (matcher.matches()) {
                fileIds.add(matcher.group(1));
            }
        }
        publication.put("files", fileIds.toString());

        System.out.println(publication);

        APIConnector connector = new APIConnector();
        int requestAttempts = 1;
        while (requestAttempts >= 0) {
            try {
                connector.createPublication(credentials, publication);
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
