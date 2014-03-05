###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_webdav_auth_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft IIS WebDAV Remote Authentication Bypass Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_affected = "Microsoft Internet Information Services version 5.0 to 6.0

  Workaround:
  Disable WebDAV or Upgrade to Microsoft IIS 7.0
  http://www.microsoft.com/technet/security/advisory/971492.mspx";

tag_impact = "Successful exploitation will let the attacker craft malicious UNICODE characters
  and send it over the context of IIS Webserver where WebDAV is enabled. As a
  result due to lack of security implementation check it will let the user fetch
  password protected directories without any valid authentications.
  Impact Level: Application";
tag_insight = "Due to the wrong implementation of UNICODE characters support (WebDAV extension)
  for Microsoft IIS Server which fails to decode the requested URL properly.
  Unicode character checks are being done after IIS Server internal security
  check, which lets the attacker execute any crafted UNICODE character in the
  HTTP requests to get information on any password protected directories without
  any authentication schema.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS09-020.mspx";
tag_summary = "The host is running Microsoft IIS Webserver with WebDAV Module and
  is prone to remote authentication bypass vulnerability.";

if(description)
{
  script_id(900711);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1535");
  script_bugtraq_id(34993);
  script_name("Microsoft IIS WebDAV Remote Authentication Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://view.samurajdata.se/psview.php?id=023287d6&amp;page=2");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/971492.mspx");
  script_xref(name : "URL" , value : "http://blog.zoller.lu/2009/05/iis-6-webdac-auth-bypass-and-data.html");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/34993.rb");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/34993.txt");

  script_description(desc);
  script_summary("Check for the version of IIS and presence of WebDAV");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

iisPort = get_http_port(default:80);
if(!iisPort){
  exit(0);
}

# For IIS WebDAV Enabled servers "MS-Author-VIA" header should be present.
# "OPTIONS" HTTP Method fetches which HTTP methods are supported for your server.
request = string("OPTIONS / HTTP/1.0 \r\n\r\n",
                 "Host: ", get_host_name(), "\r\n");
response = http_send_recv(port:iisPort, data:request);
if("200 OK" >!< response && "Server: Microsoft-IIS" >!< response)
{
  request = string("OPTIONS / HTTP/1.1 \r\n\r\n");
  response = http_send_recv(port:iisPort, data:request);
  if("200 OK" >!< response && "Server: Microsoft-IIS" >!< response){
    exit(0);
  }
}

# Check whether WebDAV Module is enabled.
if("MS-Author-Via: DAV" >!< response){
  exit(0);
}

iisVer = get_kb_item("IIS/" + iisPort + "/Ver");
if(iisVer == NULL){
  exit(0);
}

if(version_in_range(version:iisVer, test_version:"5.0", test_version2:"6.0")){
  security_hole(iisPort);
}
