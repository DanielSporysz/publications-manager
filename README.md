# WEB-P2

WEB service that offers file hosting and publication posting.

The repository also contains desktop JAVAFX client for WEB service in \PublicationsManager.

For development purposes, user database is initialised with 2 users on start up:
[login, passwword]
- admin, admin
- daniel, mistrz

# Requirements

The service listens on port 443 and is set to use the following domain names:
- web.company.com,
- pdf.company.com.

Java client:
- written in Java 8 with JAVAFX library,
- Add web.crt and pdf.crt certifices to java trusted CNs store (or disable trsuted CA checking in JVM)
  server certificate is localed in \SSL catalog 
	
Suggested way of adding the server ceritficate:
1. (add java tools to your class path)
PATH=%PATH%;"C:\Program Files\Java\jdk1.8.0_231\bin"
2. (use keytool from *\Java\jdk1.8.0_231\bin) 
keytool -importcert -alias webcompanycom -keystore "C:\Program Files\Java\jdk1.8.0_231\jre\lib\security\cacerts" -storepass changeit -file SSL\web.crt
