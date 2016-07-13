 _____ _                    _     ___                   _           
/__   \ |__  _ __ ___  __ _| |_  / __\ __ __ ___      _| | ___ _ __ 
  / /\/ '_ \| '__/ _ \/ _` | __|/ / | '__/ _` \ \ /\ / / |/ _ \ '__|
 / /  | | | | | |  __/ (_| | |_/ /__| | | (_| |\ V  V /| |  __/ |   
 \/   |_| |_|_|  \___|\__,_|\__\____/_|  \__,_| \_/\_/ |_|\___|_|   
                                                          
                      ThreatCrawler v1.1.0

about
"""""
ThreatCrawler is a tool to crawl selected RSS feeds for vulnerability and exploit listings that meet set criteria. The report is sent to specified addresses in user friendly HTML format.


version history
"""""""""""""""
v1.0.0 (08/06/16) - Initial public release.
v1.1.0 (13/07/16) - Additional sources. Separate ExploitDB reporting (HTML table sent as attachment).


installation+operation
""""""""""""""""""""""
- Compile the project in Visual Studio 2012 or higher.
- Alter the app.config entries:
-- SMTP Server.
-- SMTP Port.
-- Sender Address.
-- Mail Recipients (comma separated).
-- Bulletin Days to Check (default 14).
-- Exploit Days to Check (default 365).
-- The URI's shouldn't require adjustment.
- Define the search criteria you wish to crawl the feeds for: one line per criteria.
- Run the application.


current sources
"""""""""""""""
https://www.us-cert.gov/ncas/alerts.xml
https://feeds.feedburner.com/MalwareAdvisories
https://raw.githubusercontent.com/offensive-security/exploit-database/master/files.csv
https://www.symantec.com/xml/rss/listings.jsp?lid=latestthreats30days
http://en.0day.today/rss
http://seclists.org/rss/bugtraq.rss
http://seclists.org/rss/fulldisclosure.rss
https://nvd.nist.gov/download/nvd-rss.xml
https://rss.packetstormsecurity.com/files
https://feeds.feedburner.com/ZDI-Published-Advisories
