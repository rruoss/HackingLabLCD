##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openx_auth_bypass_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# OpenX Administrative Interface Authentication Bypass Vulnerability
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
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow remote attackers to gain administrative
  access to the affected application.
  Impact Level: Application.";
tag_affected = "OpenX version 2.8.1 and 2.8.2";

tag_insight = "The flaw is due to unspecified error related to the 'www/admin/'
  directory, which can be exploited to bypass authentication.";
tag_solution = "Upgarde to OpenX version 2.8.3 or later.
  http://www.openx.org/ad-server";
tag_summary = "This host is running OpenX and is prone authentication bypass
  vulnerability.";

if(description)
{
  script_id(800760);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-04 09:40:09 +0200 (Tue, 04 May 2010)");
  script_bugtraq_id(37457);
  script_cve_id("CVE-2009-4830");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("OpenX Administrative Interface Authentication Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/61300");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37914");
  script_xref(name : "URL" , value : "http://forum.openx.org/index.php?showtopic=503454011");

  script_description(desc);
  script_summary("Check for the version of OpenX");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("OpenX_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

openPort = get_http_port(default:80);
if(!get_port_state(openPort)){
  exit(0);
}

## Get OpenX version from KB
openVer = get_kb_item("www/" + openPort + "/openx");

if(!openVer){
  exit(0);
}

openVer = eregmatch(pattern:"^(.+) under (/.*)$", string:openVer);
if(openVer[1] != NULL)
{
  ## Check OpenX version 2.8.1, 2.8.2
  if(version_is_equal(version:openVer[1], test_version:"2.8.1") ||
     version_is_equal(version:openVer[1], test_version:"2.8.2")){
    security_hole(openPort);
  }
}
