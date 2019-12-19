# WEB-P2

WEB service that offers file uploading and downloading, using:
- ssl,
- user authentication,
- JWT tokens.

For development purposes, user database is initialised with 2 users on start up:
[login, passwword]
- admin, admin
- daniel, mistrz

# Requirements

The service listens on port 443 and is set to use the following domain names:
- web.company.com,
- pdf.company.com.

Java client:

- Add the certifices to java trusted CNs store (or disable trsuted CA checking in JVM)
PATH=%PATH%;"C:\Program Files\Java\jdk1.8.0_231\bin" 
keytool -importcert -alias webcompanycom -keystore "C:\Program Files\Java\jdk1.8.0_231\jre\lib\security\cacerts" -storepass changeit -file testowy.crt