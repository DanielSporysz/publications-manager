package dataclasses;

public class WEBCredentials {
    private String login;
    private String password;
    private String uToken;

    public WEBCredentials(String login, String password, String uToken) {
        this.login = login;
        this.password = password;
        this.uToken = uToken;

        // For development purposes
        if(this.login == null){
            this.login = "";
        }
        if(this.password == null){
            this.password = "";
        }
        if(this.uToken == null){
            this.uToken = "";
        }
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
