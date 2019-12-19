package dataclasses;

public class WEBCredentials {
    private String login;
    private String password;
    private String uToken;

    public WEBCredentials(String login, String password, String uToken) {
        if(login == null){
            login = "";
        }
        if(password == null){
            password = "";
        }
        if(uToken == null){
            uToken = "";
        }

        this.login = login;
        this.password = password;
        this.uToken = uToken;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}