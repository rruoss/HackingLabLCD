##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_sec_bypass_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# nginx Security Bypass Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let attackers to gain unauthorized access to
  restricted resources via specially crafted HTTP requests containing NTFS
  extended attributes.
  Impact Level: Application";

tag_affected = "nginx versions 0.7.52 through 1.2.0 and 1.3.0 on Windows";
tag_insight = "The flaw is due to an error when processing HTTP requests for resources
  defined via the 'location' directive.";
tag_solution = "Upgrade to nginx version 1.3.1 or 1.2.1 or later,
  For updates refer to http://nginx.org";
tag_summary = "This host is running nginx and is prone to security bypass
  vulnerability.";

if (description)
{
  script_id(803222);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2011-4963");
  script_bugtraq_id(55920);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-01 13:21:59 +0530 (Fri, 01 Feb 2013)");
  script_name("nginx Security Bypass Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/84339");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50912");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/77244");
  script_xref(name : "URL" , value : "http://english.securitylab.ru/lab/PT-2012-06");
  script_xref(name : "URL" , value : "http://nginx.org/en/security_advisories.html");
  script_xref(name : "URL" , value : "http://mailman.nginx.org/pipermail/nginx-announce/2012/000086.html");
  script_xref(name : "URL" , value : "http://blog.ptsecurity.com/2012/06/vulnerability-in-nginx-eliminated.html");

  script_description(desc);
  script_summary("Check for the version of nginx on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("nginx_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("nginx/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

# Variable Initialization
ngPort = 0;
ngVer = "";

## Exit if its not windows
if(host_runs("Windows") != "yes"){
  exit(0);
}

## Get nginx Port
ngPort = get_http_port(default:80);
if(!get_port_state(ngPort))exit(0);

ngVer =  get_kb_item(string("nginx/", ngPort, "/version"));
if(isnull(ngVer) || "unknown" >< ngVer) exit(0);

if(version_in_range(version:ngVer, test_version:"0.7.52", test_version2:"1.2.0")||
   version_is_equal(version:ngVer, test_version:"1.3.0"))
{
  security_warning(port:ngPort);
  exit(0);
}
