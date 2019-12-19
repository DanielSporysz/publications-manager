package controllers;

import dataclasses.WEBCredentials;

public class MainWindowController {
    private WEBCredentials credentials;

    public void init(WEBCredentials credentials){
        this.credentials = credentials;
        System.out.println("MainWindow has credentials!");
    }
}
