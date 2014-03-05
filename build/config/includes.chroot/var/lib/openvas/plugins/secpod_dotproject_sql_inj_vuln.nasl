###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dotproject_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# dotProject 'index.php' SQL Injection Vulnerability.
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying
  database.
  Impact Level: Application";
tag_affected = "dotProject version prior to 2.1.5";
tag_insight = "The flaw is due to an input passed to the 'ticket' parameter in
  'index.php' is not properly sanitised before being used in SQL queries.";
tag_solution = "No solution or patch is available as of 22nd September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.dotproject.net";
tag_summary = "The host is running dotProject and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(902731);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("dotProject 'index.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17829/");

  script_description(desc);
  script_summary("Check for the version of dotProject");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_dotproject_detect.nasl");
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

## Get the HTTP Port
dpPort = get_http_port(default:80);
if(!dpPort){
  exit(0);
}

## Get the version from KB
dotVer = get_version_from_kb(port:dpPort,app:"dotProject");
if(!dotVer){
  exit(0);
}

## Check for dotProject version 2.1.5
if(version_is_equal(version:dotVer, test_version:"2.1.5")){
  security_hole(dpPort);
}
