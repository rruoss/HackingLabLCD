###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xerver_http_server_code_disclosure_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Xerver HTTP Server Source Code Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to gain sensitive information
  about the application.
  Impact Level: Application";
tag_affected = "Xerver version 4.32 and prior on all platforms.";
tag_insight = "An error exists when processing HTTP requests containing '::$DATA' after
  the HTML file name which can be exploited to disclose the source code.";
tag_solution = "No solution or patch is available as of 20th October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For more info refer, http://www.javascript.nu/xerver/";
tag_summary = "This host is running Xerver HTTP Server and is prone to the Source Code
  Disclosure Vulnerability.";

if(description)
{
  script_id(801019);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-21 10:12:07 +0200 (Wed, 21 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3544");
  script_bugtraq_id(36454);
  script_name("Xerver HTTP Server Source Code Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36681");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9649");

  script_description(desc);
  script_summary("Check for the version of Xerver");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xerver_http_server_detect.nasl");
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

xerPort = get_http_port(default:80);
if(!xerPort){
  exit(0);
}

xerVer = get_kb_item("www/" + xerPort + "/Xerver");
if(xerVer != NULL)
{
  if(version_is_less_equal(version:xerVer, test_version:"4.32")){
    security_warning(xerPort);
  }
}
