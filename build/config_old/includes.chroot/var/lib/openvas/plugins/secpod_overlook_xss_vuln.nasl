###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_overlook_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# OPEN IT OverLook 'title.php' Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an
  affected site.
  Impact Level: Application";
tag_affected = "OPEN IT OverLook Verson 5.0";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed
  via the 'frame' parameter to title.php, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of
  an affected site.";
tag_solution = "No solution or patch is available as of 28th April, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.openit.it/";
tag_summary = "This host is running OverLook and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_id(902514);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_cve_id("CVE-2010-4792");
  script_bugtraq_id(43872);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("OPEN IT OverLook 'title.php' Cross Site Scripting Vulnerability");
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
  script_summary("Check for the version of OverLook");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_overlook_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41771");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62361");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/94568/overlook-xss.txt");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

## Chek Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

## Check for OverLook Verson 5.0
if(vers = get_version_from_kb(port:port,app:"OverLook"))
{
  if(version_is_equal(version:vers, test_version:"5.0")){
    security_warning(port:port);
  }
}