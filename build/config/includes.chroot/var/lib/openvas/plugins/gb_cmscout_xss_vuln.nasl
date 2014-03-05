##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cmscout_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# CMScout Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to execute arbitrary script
  code.
  Impact Level: Application.";
tag_affected = "CMScout version 2.09 and prior.";
tag_insight = "The flaw is caused by an input validation error in the 'search' module when
  processing the 'search' parameter in 'index.php' page.";
tag_solution = "No solution or patch is available as of 07th June, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.cmscout.co.za/";
tag_summary = "This host is running CMScout and is prone to Cross Site Scripting
  Vulnerability.";

if(description)
{
  script_id(800791);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-2154");
  script_bugtraq_id(40442);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("CMScout Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39986");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58996");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12806/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1288");

  script_description(desc);
  script_summary("Check the exploit string on CMScout");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_cmscout_detect.nasl");
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
include("http_keepalive.inc");

## Get HTTP Port
cmsPort = get_http_port(default:80);
if(!cmsPort){
  exit(0);
}

cmsVer = get_kb_item("www/" + cmsPort + "/CMScout");
if(!cmsVer){
  exit(0);
}

cmsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:cmsVer);
if(cmsVer[2] != NULL)
{
  filename = string(cmsVer[2] + "/index.php?page=search&menuid=5");
  host = get_host_name();
  authVariables = "search=OpenVAS+XSS+Testing&content=1&Submit=Search";

  ## Construct XSS Request
  sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.4) Gecko/2008111217 Fedora/3.0.4-1.fc10 Firefox/3.0.4\r\n",
                   "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                   "Accept-Language: en-us,en;q=0.5\r\n",
                   "Accept-Encoding: gzip,deflate\r\n",
                   "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
                   "Keep-Alive: 300\r\n",
                   "Connection: keep-alive\r\n",
                   "Referer: http://", host, filename, "\r\n",
                   "Cookie: cmscout2=1f9f3e24745df5907a131c9acb41e5ef\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                    authVariables);
  rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);

  ## Checking the response for exploit string
  if("(OpenVAS XSS Testing)" >< rcvRes){
    security_warning(cmsPort);
  }
}
