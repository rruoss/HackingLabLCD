###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mymsg_profile_sql_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# MyMsg 'profile.php' SQL Injection Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker cause SQL Injection attack
  to gain and delete sensitive information about the database used by the
  web application.
  Impact Level: Application";
tag_affected = "MyMsg version 1.0.3 and prior on all platforms.";
tag_insight = "The flaw is due to error in 'Profile.php' file. The user supplied
  data passed into the 'uid' parameter in 'Profile.php' is not properly
  sanitised before being used in SQL queries.";
tag_solution = "No solution or patch is available as of 12th October,2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mymsg.al4us.com/index.php";
tag_summary = "This host is installed with MyMsg and is prone to SQL
  Injection vulnerability.";

if(description)
{
  script_id(800952);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-15 15:35:39 +0200 (Thu, 15 Oct 2009)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3528");
  script_name("MyMsg 'profile.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35753");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9105");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51635");

  script_description(desc);
  script_summary("Check for the version of MyMsg");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mymsg_detect.nasl");
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

mymsgPort = get_http_port(default:80);
if(!mymsgPort){
  exit(0);
}

mymsgVer = get_kb_item("www/" + mymsgPort + "/MyMsg");
mymsgVer = eregmatch(pattern:"^(.+) under (/.*)$", string:mymsgVer);

if(mymsgVer[1] != NULL)
{
  if(version_is_less_equal(version:mymsgVer[1], test_version:"1.0.3")){
    security_hole(mymsgPort);
  }
}
