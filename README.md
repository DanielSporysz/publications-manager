# publications-manager

Python WEB application built using Flask and Nginx. The service provides files and publications sharing. Users can post publications and share them with other users (files including). There is the Auth0 authentication system integrated into the service. Publications-manager offers notification system when a new publication is published.

The repository also contains desktop JavaFX client for WEB service in \PublicationsManager.

For development purposes, user database is initialised with 2 users on start up:
[login, password]
- admin, admin
- daniel, mistrz

# Interesting features:
- sharing publications with everyone or with specific users,
- notification system on new publication publishing,
- integration with Auth0 authentication service.

# Security features
- secure https connection (via self signed certificates),
- strict access control thru the validation of user's login&password, sessions and JWT tokens,
- passwords hashed multiple times (10 times),
- brute force attack protection.

# Credits
This project is heavily inspired on the repository at https://github.com/bchaber/di1541 of user https://github.com/bchaber.

# WEB service requirements
The service listens on port 443 and is set to use the following domain names:
- web.company.com,
- pdf.company.com.

# Java client requirements:
- written in Java 8 with JavaFX library,
- Add web.crt and pdf.crt certificates to java trusted CNs store (or disable trusted CA checking in JVM).
 
Server certificates are located in \SSL catalog.
	
Suggested way of adding the server certificates:
1. (add java tools to your class path)
PATH=%PATH%;"C:\Program Files\Java\jdk1.8.0_231\bin"
2. (use keytool from *\Java\jdk1.8.0_231\bin) 
keytool -importcert -alias webcompanycom -keystore "C:\Program Files\Java\jdk1.8.0_231\jre\lib\security\cacerts" -storepass changeit -file SSL\web.crt

# Planned features:
- registration system,
- protection from XSRF attacks,
- blocking accounts when certain number of failed login attempts  has been made,
- system warning users about failed login attempts,
- checking the strength of user password on registration,
- adding a delay to login responses to delay brute force attacks.
