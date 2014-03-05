###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_activemq_multiple_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Apache ActiveMQ Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site
  and obtain sensitive information or cause a denial of service.
  Impact Level: Application";

tag_affected = "Apache ActiveMQ before 5.8.0";
tag_insight = "- Flaw is due to an improper sanitation of user supplied input to the
    webapp/websocket/chat.js and PortfolioPublishServlet.java scripts via
    'refresh' and 'subscribe message' parameters
  - Flaw is due to the web console not requiring any form of authentication
    for access.
  - Improper sanitation of HTTP request by the sample web applications in
    the out of box broker when it is enabled.";
tag_solution = "Upgrade to version 5.8.0 or later,
  For updates refer to http://activemq.apache.org";
tag_summary = "This host is installed with Apache ActiveMQ and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(903306);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-6092", "CVE-2012-6551", "CVE-2013-3060");
  script_bugtraq_id(59400, 59401, 59402);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vetor", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-27 12:08:18 +0530 (Sat, 27 Apr 2013)");
  script_name("Apache ActiveMQ Multiple Vulnerabilities");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/92707");
  script_xref(name : "URL" , value : "http://www.osvdb.com/92706");
  script_xref(name : "URL" , value : "http://www.osvdb.com/92705");
  script_xref(name : "URL" , value : "http://www.osvdb.com/92709");
  script_xref(name : "URL" , value : "http://www.osvdb.com/92708");
  script_xref(name : "URL" , value : "https://issues.apache.org/jira/browse/AMQ-4124");
  script_xref(name : "URL" , value : "http://activemq.apache.org/activemq-580-release.html");
  script_xref(name : "URL" , value : "https://issues.apache.org/jira/secure/ReleaseNote.jspa?projectId=12311210&amp;version=12323282");
  script_summary("Check if Apache ActiveMQ is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8161);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
req = "";
res = "";
url = "";

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
    ## Construct the attack request
    url = dir + "/demo/portfolioPublish?refresh=<script>alert(document.cookie)</script>&stocks=XSS-Test";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
           pattern:"<script>alert\(document.cookie\)</script>",
                                    extra_check:">Published <"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
