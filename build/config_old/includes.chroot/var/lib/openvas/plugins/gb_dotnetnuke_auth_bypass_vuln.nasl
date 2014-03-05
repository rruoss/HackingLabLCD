###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotnetnuke_auth_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# DotNetNuke Identity Authentication Bypass Vulnerability
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
tag_impact = "Successful exploitation could allows remote attackers to bypass security
  restrictions via unknown vectors related to a 'unique id' and impersonate
  other users and possibly gain elevated pivileges.
  Impact Level: Application";
tag_affected = "DotNetNuke versions 4.4.1 to 4.8.4.";
tag_insight = "The vulnerability is caused due improper validation of a user identity.";
tag_solution = "Upgrade to DotNetNuke version 4.9.0 or latest
  For updates refer to http://www.dotnetnuke.com/";
tag_summary = "The host is installed with DotNetNuke and is prone to Authentication
  Bypass vulnerability.";

if(description)
{
  script_id(800684);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-7100");
  script_bugtraq_id(31145);
  script_name("DotNetNuke Identity Authentication Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/45081");
  script_xref(name : "URL" , value : "http://www.dotnetnuke.com/News/SecurityPolicy/Securitybulletinno21/tabid/1174/Default.aspx");

  script_description(desc);
  script_summary("Check for the vVersion of DotNetNuke");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH ");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_detect.nasl");
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

dnnPort = get_http_port(default:80);
if(!dnnPort){
  exit(0);
}

dnnVer = get_kb_item("www/" + dnnPort + "/DotNetNuke");
if(!dnnVer){
  exit(0);
}

dnnVer = eregmatch(pattern:"^(.+) under (/.*)$", string:dnnVer);
if(dnnVer[1] != NULL)
{
  if(version_in_range(version:dnnVer[1], test_version:"4.4.1", test_version2:"4.8.4")){
    security_hole(dnnPort);
  }
}
