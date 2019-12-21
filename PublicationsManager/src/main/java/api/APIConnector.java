package api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jsoup.Connection;
import org.jsoup.Jsoup;

import java.io.IOException;
import java.util.Map;

public class APIConnector {

    private final String url = "https://web.company.com/api";

    public String fetchToken(String login, String password) throws APIException {
        try {
            Connection.Response response =
                    Jsoup.connect(url + "/utoken")
                            .userAgent("Mozilla")
                            .timeout(10 * 1000)
                            .method(Connection.Method.GET)
                            .data("login", login)
                            .data("password", password)
                            .followRedirects(true)
                            .ignoreContentType(true)
                            .execute();

            // jsoup throws an Exception when server responds with 401, don't handle that here
            if (response.statusCode() == 201) {
                ObjectMapper mapper = new ObjectMapper();
                String json = response.body();
                Map<String, String> map = mapper.readValue(json, Map.class);
                return map.get("auth_token");
            } else {
                throw new APIException("Server responded with unknown response.");
            }
        } catch (IOException ioe) {
            // jsoup throws exception when server responds with 401 - failed log in
            if (ioe.getMessage().equals("HTTP error fetching URL")) {
                throw new APIException("Incorrect credentials.");
            } else {
                throw new APIException(ioe.getLocalizedMessage());
            }
        }
    }
}
