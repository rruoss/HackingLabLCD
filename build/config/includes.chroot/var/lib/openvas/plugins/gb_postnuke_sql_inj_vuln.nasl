##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postnuke_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# PostNuke modload Module 'sid' Parameter SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to access, modify or delete
  information in the underlying database.
  Impact Level: Application.";
tag_affected = "PostNuke version 0.764";

tag_insight = "The flaw exists due to failure to sufficiently sanitize user-supplied data to
  'modules.php' via 'sid' parameter before using it in an SQL query.";
tag_solution = "No solution or patch is available as of 7th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.postnuke.com/";
tag_summary = "This host is running PostNuke and is prone SQL injection vulnerability.";

if(description)
{
  script_id(800771);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1713");
  script_bugtraq_id(39713);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PostNuke modload Module 'sid' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58204");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12410");
 
  script_description(desc);
  script_summary("Check for the version of PostNuke");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_zikula_detect.nasl");
  script_require_ports("Services/www", 80);
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

pnPort = get_http_port(default:80);
if(!get_port_state(pnPort)){
  exit(0);
}

## Get PostNuke version from KB
pnVer = get_kb_item("www/"+ pnPort + "/postnuke");
if(!pnVer){
 exit(0);
}

pnVer = eregmatch(pattern:"^(.+) under (/.*)$", string:pnVer);

## Check for the PostNuke version 0.764 => 0.76
if(pnVer[1] != NULL)
{
  if(version_is_equal(version:pnVer[1], test_version:"0.76")){
    security_hole(pnPort); 
  }
}
