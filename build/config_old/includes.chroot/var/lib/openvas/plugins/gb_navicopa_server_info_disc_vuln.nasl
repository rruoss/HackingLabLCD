###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_navicopa_server_info_disc_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# NaviCOPA Web Server Source Code Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to display the source code
  of arbitrary files (e.g. PHP) instead of an expected HTML response.
  Impact Level: Application";
tag_affected = "NaviCOPA Web Server version 3.0.1.2 and prior on windows.";
tag_insight = "This issue is caused by an error when handling requests with the '%20' string
  appended to the file extension.";
tag_solution = "Upgrade to the NaviCOPA Web Server version 3.0.1.3 or later.
  For updates refer to http://www.navicopa.com/download.html";
tag_summary = "The host is running NaviCOPA Web Server and is prone to Source Code
  Disclosure vulnerability.";

if(description)
{
  script_id(800411);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-09 13:17:56 +0100 (Sat, 09 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4529");
  script_name("NaviCOPA Web Server Source Code Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37014");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53799");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2927");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.org/0910-exploits/navicopa-disclose.txt");

  script_description(desc);
  script_summary("Check for version of NaviCOPA Web Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_navicopa_server_detect.nasl");
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

ncpaPort = get_http_port(default:80);
if(!ncpaPort){
  exit(0);
}

#Grep for KB Value
ncpaVer = get_kb_item("NaviCOPA/" + ncpaPort + "/Ver");
if(isnull(ncpaVer)){
  exit(0);
}

#check for the  NaviCOPA verison 3.0.1.2 (3.01.2)
if(version_is_less_equal(version:ncpaVer, test_version:"3.01.2")){
  security_warning(ncpaPort);
}
