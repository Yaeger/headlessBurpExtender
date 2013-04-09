/*
 * Burp Headless scanner: 2013 Daniel del Hoyo <danieldelhoyo AT zalando DOT de>
 * Modification of sodapop burp extension: Copyright (C) 2010 Paul Haas <phaas AT redspin DOT com>
 * Licensed under the GNU Public License version 3.0 or greater
 *
 * Advanced Burp Suite Automation :
 * This tool accepts a URL, output_name, and an optional cookie string
 * It adds the URL's domain to Burp's scope then begins spidering from the
 * provided URL. Each request/reply is scanned passively for issues, and any
 * URLs with parameters are sent to Burp's active scanner. When testing is
 * finished, a session file is created with the results. The optional cookie
 * string is appended to all requests and is used to test applications requring
 * authentication.
 *
 * Output Files:
 *      output_name.zip - Burp's session file
 *      output_name.urls - List of URLs seen during testing
 *      output_name.issues - Full detail list of issues in tab delimited format
 *
 * See http://portswigger.net/misc/ for IBurpExtender API info and code
 */

package burp;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import java.net.URL;

import java.util.ConcurrentModificationException;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender {
    public IBurpExtenderCallbacks mcallBacks;
    public URL url;
    public File outsession;
    public BufferedWriter outissues;
    public BufferedWriter outurls;
    public String cookies;
    public Date lastRequest;
    public boolean scanQuit = false;                          // Quit after scanning: false = yes, true = prompt
    public boolean monitorThread = false;
    public Vector<IScanQueueItem> scanqueue = new Vector<IScanQueueItem>();
    public File restoreState = new File("configuration.zip"); // Configuration used for command-line scanning
    public int delay = 30;                                    // Number of seconds to wait in loop for scanning and
                                                              // spidering
                                                              // to complete

    String header = "<html><head><style type=\"text/css\">\n"
            + "H1 { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 1.6em; font-weight: bold; line-height: 1.0em; }\n"
            + "H2 { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 0.8em; font-weight: bold; line-height: 1.0em; }\n"
            + ".TOCH0 { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 1.0em; font-weight: bold; line-height: 0.6em; }\n"
            + ".TOCH1 { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 0.8em; text-indent: 30px; line-height: 0.5em; }\n"
            + ".TOCH2 { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 0.7em; text-indent: 50px; line-height: 0.0em; }\n"
            + ".BODH0 { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 1.6em; font-weight: bold; line-height: 2.0em; }\n"
            + ".BODH1 { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 1.3em; font-weight: bold; line-height: 2.0em; }\n"
            + ".BODH2 { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 1.0em; font-weight: bold; line-height: 2.0em; }\n"
            + ".PREVNEXT { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 0.6em; color: gray }\n"
            + ".TEXT { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 0.8em; }\n"
            + "TD { font-family: Verdana, Arial, Helvetica, sans-serif; font-size: 0.8em; }\n"
            + ".HIGHLIGHT { background-color: yellow; }\n"
            + ".RR_SCROLL { overflow-x: visible; overflow-y: auto; height: 50px; }\n"
            + ".RR_TABLE_SCREEN { background-color: #e8e8e8; width:100%; }\n"
            + ".RR_TABLE_PRINTER { background-color: #e8e8e8; width:100%; border-width: medium; border-style: solid; border-color: gray; }\n"
            + "</style>\n" + "</head>\n" + "<body>";

    String alertTypes = "<p class=\"TOCH0\"><a href=\"#1\">1. SQL injection</a></p>"
            + "<p class=\"TOCH0\"><a href=\"#2\">2. Password field with autocomplete enabled</a></p>"
            + "<p class=\"TOCH0\"><a href=\"#3\">3. User agent-dependent response</a></p>"
            + "<p class=\"TOCH0\"><a href=\"#4\">4. Cookie scoped to parent domain</a></p>"
            + "<p class=\"TOCH0\"><a href=\"#5\">5.Cross-domain Referer leakage</a></p>"
            + "<p class=\"TOCH0\"><a href=\"#6\">6. Cross-domain script include</a></p>"
            + "<p class=\"TOCH0\"><a href=\"#7\">7. Cookie without HttpOnly flag set</a></p>"
            + "<p class=\"TOCH0\"><a href=\"#8\">8. Email addresses disclosed</a></p>"
            + "<p class=\"TOCH0\"><a href=\"#9\">9. Credit card numbers disclosed</a></p>"
            + "<p class=\"TOCH0\"><a href=\"#10\">10. Content type incorrectly stated</a></p>"
            + "<p class=\"TOCH0\"><a href=\"#11\">11. Robots.txt file</a></p>"
            + "<p class=\"TOCH0\"><a href=\"#12\">12.Others</a></p>";

    public int[] issueCounter = new int[20];

    // Called to handle command line arguments passed to Burp
    public void setCommandLineArgs(final String[] args) {
        if (!(args.length == 2 | args.length == 3)) {
            System.out.println("Automated Burp Suite spidering and scanning tool\n");
            System.out.println("Usage: URL OUTNAME {COOKIE STRING}");
            System.out.println("\tURL = Start URL to start spidering from");
            System.out.println("\tOUTNAME = Filename w/o extension to save files");
            System.out.println("\tCookie = Optional cookie string to append to all HTTP requests");
            System.exit(1);
        }

        try {

            // If URL doesn't start with a protocol, prepend one
            if (args[0].startsWith("http")) {
                url = new URL(args[0]);
            } else {
                url = new URL("http://" + args[0]);
            }

            if (url.getPort() == -1) // Java reverts to port=-1 if not explicitly specified
            {
                url = new URL(url.getProtocol(), url.getHost(), url.getDefaultPort(), url.getFile());
            }

            if (url.getFile() == "") // Java will assume a blank path if you do not supply one
            {
                url = new URL(url.getProtocol(), url.getHost(), url.getPort(), "/");
            }

            outsession = new File(args[1] + ".zip");

            File aFile = new File(args[1] + "_issues.html");
            outissues = new BufferedWriter(new FileWriter(aFile, aFile.exists()));
            outissues.write(header);

            // Date and reporter
            Date currentDate = new java.util.Date();
            outissues.write("<body>\n"
                    + "<span class=\"TEXT\">Report generated by <a href=\"http://portswigger.net/scanner\">Burp Scanner Headless plugin</a> at "
                    + currentDate.toString() + "</span><br><br>\n" + "<hr>\n" + "<h1>Contents</h1>");

            outissues.write(alertTypes);

            // URLs
            aFile = new File(args[1] + "_urls.html");
            outurls = new BufferedWriter(new FileWriter(aFile, aFile.exists()));

            if (args.length == 3) // Set cookies if supplied
            {
                cookies = "Cookie: " + args[2];
            }
        } catch (java.net.MalformedURLException e) {
            System.out.println("Error converting string '" + args[0] + "' into URL: " + e.getMessage());
            System.exit(2);
        } catch (IOException e) {
            System.out.println("Error during IO: " + e.getMessage());
            System.exit(3);
        } catch (Exception e) {
            System.out.println("Other error occurred during commandline URL conversion: " + e.getMessage());
            System.exit(4);
        }

        return;
    }

    // This function is called a single time as Burp Suite loads and needs to return
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        mcallBacks = callbacks;

        for (int i = 0; i < 20; i++) {
            issueCounter[i] = 1;
        }

        mcallBacks.setProxyInterceptionEnabled(false);
        mcallBacks.setExtensionName("Headless scanning");

        mcallBacks.issueAlert("Attempting to restore state from '" + restoreState + "'");
        try {
            mcallBacks.restoreState(restoreState);
        } catch (Exception e) {
            System.out.println("Unable to restore state from '" + restoreState + "': " + e.getMessage());
            mcallBacks.exitSuite(false); // Unconditional exit
        }

        mcallBacks.issueAlert("Adding " + url.getHost() + " to scope, spider and scanner");
        if (cookies != null) {
            mcallBacks.issueAlert("Including '" + cookies
                    + "' to all in-scope requests. This will not appear in Burp's logs.");
        } else {
            mcallBacks.issueAlert("No cookies provided, using cookies provided during spider");
        }

        try {
            URL urlScope = new URL(url.getProtocol(), url.getHost(), url.getPort(), "/");
            if (!mcallBacks.isInScope(urlScope)) {
                mcallBacks.includeInScope(urlScope);
            }

            lastRequest = new Date();
            mcallBacks.issueAlert("Starting spider on " + url + " at " + lastRequest);
            mcallBacks.sendToSpider(url);
            // mcallBacks.sendToSpider(urlScope);
        } catch (Exception e) {
            System.out.println("Could not add URL to scope and spider, quitting: " + e.getMessage());
            mcallBacks.exitSuite(false); // Unconditional exit
        }

        return;
    }

    // Called each time a HTTP request or HTTP reply is generated from a Burp tool
    public void processHttpMessage(final String toolName, final boolean messageIsRequest,
            IHttpRequestResponse messageInfo) {

        // Spider Reply: Add URL to passive and active scan
        if (toolName.equals("spider")) {

            if (messageIsRequest) {

                // Update last request time and append cookies to request
                lastRequest = new Date();
                messageInfo = appendCookies(messageInfo);
            }
            // Scan and save URLS that are not 404 (Not Found)
            else {

                // Create a single instance of a monitorThread
                if (!monitorThread) {
                    monitorThread = true;
                    monitorScan(messageInfo);
                }
                // Send message to passive and active scanner
                else {
                    spiderToScanner(messageInfo);
                }

                try {

                    // Write URL to file (Would be nice to include Request body after tab)
                    if (mcallBacks.getHelpers().analyzeResponse(messageInfo.getResponse()).getStatusCode() != 404) {
                        outurls.write(getHostFromRespone(messageInfo) + "\n");
                    }
                } catch (Exception e) {
                    System.out.println("Could not add URL to file: " + e.getMessage());
                }

            }
        }

        return;
    }

    // Called whenever a scan issue occurs
    public void newScanIssue(final IScanIssue issue) {
        try {

            // Filter Information issue messages to STDOUT
            if (issue.getSeverity() != "Information") {
                System.out.println("scanner: " + issue.getSeverity() + " " + issue.getIssueName() + ": "
                        + issue.getUrl());
            }
            // Save session each time a High Finding is found
            else if (issue.getSeverity() == "High") {
                mcallBacks.saveState(outsession);
            }

            outissues.write(generateHTMLissue(issue));

        } catch (Exception e) {
            System.out.println("Error writing to issue file: " + e.getMessage());
        }

        return;
    }

    private String generateHTMLissue(final IScanIssue issue) {

        int type = getType(issue.getIssueName());
        int counter = issueCounter[type];

        // reference
        String refid = counter == 1 ? "" + type : type + "." + counter;

        // previous
        String prev = (counter == 1 || counter == 2) ? "" + type : type + "." + (counter - 1);

        // next
        String next = type + "." + (counter + 1);

        String id = type + "." + counter + " ";

        String recommendation = issue.getRemediationDetail() == null ? "Unknown" : issue.getRemediationDetail();

        String htmlIssue = "\n<br>\n<hr>\n<span class=\"BODH1\" id=" + refid + ">" + id + issue.getUrl() + "</span>\n"
                + "&nbsp;<a class=\"PREVNEXT\" href=\"#" + prev + "\">previous</a>\n"
                + "&nbsp;<a class=\"PREVNEXT\" href=\"#" + next + "\">next</a>" + "<br>\n" + "<h2>Summary</h2>\n"
                + "<table cellpadding=\"0\" cellspacing=\"0\">\n" + "<tr>\n" + "<td>Severity:&nbsp;&nbsp;</td>\n"
                + "<td><b>" + issue.getSeverity() + "</b></td>\n" + "</tr>\n" + "<tr>\n"
                + "<td>Confidence:&nbsp;&nbsp;</td>\n" + "<td><b>" + issue.getConfidence() + "</b></td>\n" + "</tr>\n"
                + "<tr>\n" + "<td>Host:&nbsp;&nbsp;</td>\n" + "<td><b>" + issue.getUrl().getHost() + "</b></td>\n"
                + "</tr>\n" + "<tr>\n" + "<td>Path:&nbsp;&nbsp;</td>\n" + "<td><b>" + issue
                .getUrl().getPath() + "</b></td>\n" + "</tr>\n" + "</table>\n" + "<h2>Issue detail</h2>\n"
                + "<span class=\"TEXT\">" + issue.getIssueDetail() + "</span>" + "<h2>Background</h2>\n"
                + "<span class=\"TEXT\">" + issue.getIssueBackground() + "</span>" + "<h2>Remediation</h2>\n"
                + "<span class=\"TEXT\">" + issue.getRemediationBackground() + "</span>"
                + "<h2>Remediation details</h2>\n" + "<span class=\"TEXT\">" + recommendation + "</span>"
                + "\n<h2>Request</h2>\n"
                + "<div class=\"RR_SCROLL\"><table class=\"RR_TABLE_SCREEN\" cellpadding=\"5\" cellspacing=\"0\"><tr><td><span>"
                + mcallBacks.getHelpers().analyzeRequest(issue.getHttpMessages()[0].getRequest()).getHeaders()
                .toString() + "</span></td></tr></table></div>" + "\n<h2>Response</h2>\n"
                + "<div class=\"RR_SCROLL\"><table class=\"RR_TABLE_SCREEN\" cellpadding=\"5\" cellspacing=\"0\"><tr><td><span>"
                + mcallBacks.getHelpers().analyzeResponse(issue.getHttpMessages()[0].getResponse()).getHeaders()
                .toString() + "</b><br></span></td></tr></table></div>" + "\n<br/>";

        issueCounter[type]++;

        return htmlIssue;
    }

    private int getType(final String type) {

        // classify some of the most common vulnerabilities under a specific types
        if (type.equals("SQL injection")) {
            return 1;

        } else if (type.equals("Password field with autocomplete enabled")) {
            return 2;

        } else if (type.equals("User agent-dependent response")) {
            return 3;

        } else if (type.equals("Cookie scoped to parent domain")) {
            return 4;

        } else if (type.equals("Cross-domain Referer leakage")) {
            return 5;

        } else if (type.equals("Cross-domain script include")) {
            return 6;

        } else if (type.equals("Cookie without HttpOnly flag set")) {
            return 7;

        } else if (type.equals("Email addresses disclosed")) {
            return 8;

        } else if (type.equals("Credit card numbers disclosed")) {
            return 9;

        } else if (type.equals("Content type incorrectly stated")) {
            return 10;

        } else if (type.equals("Robots.txt file")) {
            return 11;

        } else {
            return 12;
        }

    }

    // Called during proxy requests, not needed with processHttpMessage
    public byte[] processProxyMessage(final int messageReference, final boolean messageIsRequest,
            final String remoteHost, final int remotePort, final boolean serviceIsHttps, final String httpMethod,
            final String url, final String resourceType, final String statusCode, final String responseContentType,
            final byte[] message, final int[] interceptAction) {
        return message;
    }

    // Called when application is closed
    public void applicationClosing() {
        try {
            outurls.close();
            outissues.close();
        } catch (Exception e) {
            System.out.println("Could not close files, quitting Burp Suite anyway: " + e.getMessage());
        }

        return;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Called for a single thread to keep an eye on Burp's spider log, quit after 1 minute of no activity
    public int monitorScan(final IHttpRequestResponse messageInfo) {
        try {
            Date currentTime = new Date();
            mcallBacks.issueAlert("Monitor thread started at " + currentTime + " and waiting for spider to complete");

            // Continue waiting while lastRequest happened less than 1 minute ago
            while (lastRequest.getTime() + (delay * 100) > currentTime.getTime()) {
                currentTime = new Date();
                Thread.currentThread().yield();
                Thread.currentThread().sleep(delay * 1000);
            }

            mcallBacks.issueAlert("Spidering complete at " + lastRequest + ", waiting for scanning completion");
            while (scanqueue.size() != 0) {
                Iterator<IScanQueueItem> iterator = scanqueue.iterator();
                while (iterator.hasNext()) {
                    try {
                        IScanQueueItem isqi = iterator.next();

                        // Remove scan item from queue if it is finished
                        if (isqi.getPercentageComplete() == 100) {
                            iterator.remove();
                        } else if (isqi.getStatus() == "abandoned - too many errors"
                                | isqi.getStatus() == "waiting to cancel") {
                            iterator.remove();
                        }
                    }
                    // See http://javabeanz.wordpress.com/2007/06/29/iterator-vs-enumeration/
                    catch (ConcurrentModificationException e) {
                        System.out.println("ConcurrentModificationException in monitorScan: " + e.getMessage());
                        break;
                    }
                }

                currentTime = new Date();
                mcallBacks.issueAlert(scanqueue.size() + " remaining objects in scan queue at " + currentTime);

                // Wait another 1 minute for completion
                Thread.currentThread().yield();
                Thread.currentThread().sleep(delay * 1000);
            }

            // Save results and quit
            currentTime = new Date();
            mcallBacks.issueAlert("Scanning complete at " + currentTime + ". Saving session results to " + outsession);
            mcallBacks.saveState(outsession);
            mcallBacks.exitSuite(scanQuit);
        } catch (Exception e) {
            System.out.println("Monitor thread encountered an unrecoverable error, saving files and quitting:"
                    + e.getMessage());

            // We might not be able to save our session, but try just in case
            try {
                mcallBacks.saveState(outsession);
            } catch (Exception exception) {
                exception.printStackTrace();
            }

            mcallBacks.exitSuite(scanQuit);
            return 1;
        }

        return 0;
    }

    // Called for each spider server reply to pass message on to passive/active scanning
    private void spiderToScanner(final IHttpRequestResponse messageInfo) {
        try {

            // Passively test everything
            Boolean serviceIsHttps = messageInfo.getHttpService().getProtocol() == "https" ? true : false;
            mcallBacks.doPassiveScan(messageInfo.getHttpService().getHost(), messageInfo.getHttpService().getPort(),
                serviceIsHttps, messageInfo.getRequest(), messageInfo.getResponse());

            URL myURL = new URL(getHostFromRespone(messageInfo));

            // Only actively test items in scope

            if (mcallBacks.isInScope(myURL)) {
                boolean activescan = false;
                boolean inqueue = false;
                byte[] request = messageInfo.getRequest();
                mcallBacks.getHelpers().analyzeRequest(request);

                List<IParameter> parameterList = mcallBacks.getHelpers().analyzeRequest(messageInfo.getRequest())
                                                           .getParameters();

                boolean inUrl = false;
                for (int i = 0; i < parameterList.size(); i++) {
                    IParameter iParameter = parameterList.get(i);

                    if (iParameter.getType() == IParameter.PARAM_URL) {
                        inUrl = true;
                    }

                    if (iParameter.getType() == IParameter.PARAM_COOKIE && inUrl) {
                        activescan = true;
                        break;
                    }

                }

                // Perform active testing only of URL has non cookie parameters
                if (activescan) {

                    // Add to active scan list and scan vector
                    IScanQueueItem isqi = mcallBacks.doActiveScan(messageInfo.getHttpService().getHost(),
                            messageInfo.getHttpService().getPort(), serviceIsHttps, messageInfo.getRequest());
                    scanqueue.add(isqi);
                }
            }
        } catch (Exception e) {
            System.out.println("Error in spiderToScanner:" + e.getMessage());
        }
    }

    private String getHostFromRespone(final IHttpRequestResponse response) {

        String re1 = "((?:[a-z][a-z0-9_]*))"; // Variable Name 1
        Pattern p = Pattern.compile(re1, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        Matcher m = p.matcher(url.toString());
        String protocol = "http://";
        if (m.find()) {
            protocol = m.group(1) + "://";
        }

        String hostname = protocol;
        hostname = hostname
                + mcallBacks.getHelpers().analyzeRequest(response.getRequest()).getHeaders().get(1).substring(6);
        hostname = hostname
                + mcallBacks.getHelpers().analyzeRequest(response.getRequest()).getHeaders().get(0).substring(4,
                    mcallBacks.getHelpers().analyzeRequest(response.getRequest()).getHeaders().get(0).length() - 8);
        return hostname;

    }

    // Append/Modify HTTP cookies for all in-scope requests
    private IHttpRequestResponse appendCookies(final IHttpRequestResponse messageInfo) {
        try {
            URL myURL = new URL(getHostFromRespone(messageInfo));

            // If URL is in scope and we have cmdline specified cookies, append them to request
            if ((cookies != null) && mcallBacks.isInScope(new URL(getHostFromRespone(messageInfo)))) {
                byte[] request = messageInfo.getRequest();
                String rrequestString = new String(request);

                Pattern pattern = Pattern.compile("^Cookie:\\s(.*?)$",
                        Pattern.DOTALL | Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
                Matcher matcher = pattern.matcher(rrequestString);
                if (matcher.find()) {
                    rrequestString = matcher.replaceFirst(cookies);
                } else {
                    pattern = Pattern.compile("\r\n\r\n");
                    matcher = pattern.matcher(rrequestString);
                    rrequestString = matcher.replaceFirst("\r\n" + cookies + "\r\n\r\n");
                }

                request = rrequestString.getBytes();
                messageInfo.setRequest(request);
            }
        } catch (Exception e) {
            System.out.println("Error setting Cookie Header: " + e.getMessage());
        }

        return messageInfo;
    }

}
