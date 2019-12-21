package controllers;

import dataclasses.WEBCredentials;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.Label;


public class MainWindowController {
    @FXML
    private ListView fileList;
    @FXML
    private ListView pubList;
    @FXML
    private Label topGreeting;

    private WEBCredentials credentials;

    public void init(WEBCredentials credentials){
        this.credentials = credentials;
        topGreeting.setText("Welcome " + credentials.getLogin() + "!");
        initFileList();
        initPubList();
    }

    private void initFileList(){
        ObservableList<String> items =FXCollections.observableArrayList (
                "Single", "Double", "Suite", "Family App");
        fileList.setItems(items);

    }

    private void initPubList(){
        //TODO
    }

}
