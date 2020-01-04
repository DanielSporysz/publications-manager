package api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dataclasses.WEBCredentials;
import org.jsoup.Connection;
import org.jsoup.Jsoup;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Map;

public class APIConnector {

    private final String url = "https://web.company.com/api";

    public String fetchAuthToken(String login, String password) throws APIException {
        try {
            Connection.Response response =
                    Jsoup.connect(url + "/auth-token")
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
            throw new APIException(ioe.getLocalizedMessage());
        }
    }

    public BufferedInputStream downloadFile(WEBCredentials credentials, String fid) throws APIException {
        try {
            Connection.Response response =
                    Jsoup.connect(url + "/file/download")
                            .userAgent("Mozilla")
                            .timeout(10 * 1000)
                            .method(Connection.Method.GET)
                            .data("auth_token", credentials.getUToken())
                            .data("fid", fid)
                            .followRedirects(true)
                            .ignoreContentType(true)
                            .maxBodySize(0)
                            .execute();

            if (response.statusCode() == 200) {
                return response.bodyStream();
            } else {
                throw new APIException("Server responded with unknown response.");
            }
        } catch (IOException e) {
            e.printStackTrace();
            throw new APIException(e.getLocalizedMessage());
        }
    }

    public Map<String, String> fetchFileList(WEBCredentials credentials) throws APIException {
        try {
            Connection.Response response =
                    Jsoup.connect(url + "/file-list")
                            .userAgent("Mozilla")
                            .timeout(10 * 1000)
                            .method(Connection.Method.GET)
                            .data("auth_token", credentials.getUToken())
                            .followRedirects(true)
                            .ignoreContentType(true)
                            .execute();

            return getMapFromResponse(response);
        } catch (IOException e) {
            throw new APIException(e.getLocalizedMessage());
        }
    }

    public void uploadFile(WEBCredentials credentials, File file) throws APIException {
        try {
            FileInputStream upFile = new FileInputStream(file);
            Connection.Response response =
                    Jsoup.connect(url + "/file/upload")
                            .userAgent("Mozilla")
                            .timeout(10 * 1000)
                            .method(Connection.Method.POST)
                            .data("auth_token", credentials.getUToken())
                            .data("file", file.getName(), upFile)
                            .followRedirects(true)
                            .ignoreContentType(true)
                            .execute();

            upFile.close();
        } catch (IOException e) {
            throw new APIException(e.getLocalizedMessage());
        }
    }

    public void deleteFile(WEBCredentials credentials, String fid) throws APIException {
        try {
            Connection.Response response =
                    Jsoup.connect(url + "/file/delete")
                            .userAgent("Mozilla")
                            .timeout(10 * 1000)
                            .method(Connection.Method.DELETE)
                            .data("auth_token", credentials.getUToken())
                            .data("fid", fid)
                            .followRedirects(true)
                            .ignoreContentType(true)
                            .execute();
        } catch (IOException e) {
            throw new APIException(e.getLocalizedMessage());
        }
    }

    public Map<String, String> fetchPubList(WEBCredentials credentials) throws APIException {
        try {
            Connection.Response response =
                    Jsoup.connect(url + "/pub-list")
                            .userAgent("Mozilla")
                            .timeout(10 * 1000)
                            .method(Connection.Method.GET)
                            .data("auth_token", credentials.getUToken())
                            .followRedirects(true)
                            .ignoreContentType(true)
                            .execute();

            return getMapFromResponse(response);
        } catch (IOException e) {
            throw new APIException(e.getLocalizedMessage());
        }
    }

    private Map<String, String> getMapFromResponse(Connection.Response response) throws APIException {
        if (response.statusCode() == 201) {
            ObjectMapper mapper = new ObjectMapper();
            String json = response.body();
            Map<String, String> map = null;
            try {
                map = mapper.readValue(json, Map.class);
            } catch (IOException e) {
                e.printStackTrace();
                throw new APIException("There's been an error parsing the response from server.");
            }
            return map;
        } else {
            throw new APIException("Server responded with unknown response.");
        }
    }

    public void createPublication(WEBCredentials credentials, Map<String, String> publication) throws APIException {
        String json;
        try {
            json = new ObjectMapper().writeValueAsString(publication);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return;
        }

        try {
            Connection.Response response =
                    Jsoup.connect(url + "/new-pub")
                            .userAgent("Mozilla")
                            .timeout(10 * 1000)
                            .method(Connection.Method.POST)
                            .data("auth_token", credentials.getUToken())
                            .data("publication", json)
                            .followRedirects(true)
                            .ignoreContentType(true)
                            .execute();
        } catch (IOException e) {
            throw new APIException(e.getLocalizedMessage());
        }
    }

    public void updatePublication(WEBCredentials credentials, Map<String, String> publication, String pid) throws APIException {
        String json;
        try {
            json = new ObjectMapper().writeValueAsString(publication);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return;
        }

        try {
            Connection.Response response =
                    Jsoup.connect(url + "/update-pub")
                            .userAgent("Mozilla")
                            .timeout(10 * 1000)
                            .method(Connection.Method.PUT)
                            .data("auth_token", credentials.getUToken())
                            .data("publication", json)
                            .data("pid", pid)
                            .followRedirects(true)
                            .ignoreContentType(true)
                            .execute();
        } catch (IOException e) {
            throw new APIException(e.getLocalizedMessage());
        }
    }

    public void deletePub(WEBCredentials credentials, String pid) throws APIException {
        try {
            Connection.Response response =
                    Jsoup.connect(url + "/del-pub")
                            .userAgent("Mozilla")
                            .timeout(10 * 1000)
                            .method(Connection.Method.DELETE)
                            .data("auth_token", credentials.getUToken())
                            .data("pid", pid)
                            .followRedirects(true)
                            .ignoreContentType(true)
                            .execute();
        } catch (IOException e) {
            throw new APIException(e.getLocalizedMessage());
        }
    }
}
