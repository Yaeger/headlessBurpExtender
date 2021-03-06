#!/bin/sh
#Copyright (C) 2010 Paul Haas <phaas AT redspin DOT com> 
#Licensed under the GNU Public License version 3.0 or greater
#Automates Burp Suite Professional using the IBurpExtender Interface

# Compile and Jar our BurpExtender class, and quit if any errors occur
javac burp/*.java 
jar -cf BurpExtender.jar burp/BurpExtender.class
# Use the latest version of Burp Suite in the directory
burp=$(ls -1t burp*.jar | head -n1)
# Run Burp in headless mode with 1GB of memory, passing any command line argument
java -Xmx1024m -Djava.awt.headless=true -classpath BurpExtender.jar:"$burp" "$@"
# Run Burp in awt mode with 1GB of memory, passing any command line argument
#java -Xmx1024m -classpath  BurpExtender.jar:"$burp" burp.StartBurp www.meneame.net mene "CookieTest=Cookie"
