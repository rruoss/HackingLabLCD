###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_alien_vault_ossim_mult_sql_inj_vuln.nasl 29 2013-10-30 14:01:12Z veerendragg $
#
# AlienVault OSSIM 'date_from' Parameter Multiple SQL Injection Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
###############################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804028";
CPE = "cpe:/a:alienvault:open_source_security_information_management";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 29 $");
  script_cve_id("CVE-2013-5967");
  script_bugtraq_id(62790);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-30 15:01:12 +0100 (Mi, 30. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-17 15:25:41 +0530 (Thu, 17 Oct 2013)");
  script_name("AlienVault OSSIM 'date_from' Parameter Multiple SQL Injection Vulnerabilities");

  tag_summary =
"This host is running AlienVault OSSIM and is prone to multiple sql injection
vulnerabilities.";

  tag_vuldetect =
"Send a HTTP GET request and check whether it is able to execute sql query
or not.";

  tag_insight =
"Multiple flaws are due to improper sanitation of user-supplied input to the
'date_form' parameter when displaying radar reports.";

  tag_impact =
"Successful exploitation will allow remote attackers to inject or manipulate
SQL queries in the back-end database, allowing for the manipulation or
disclosure of arbitrary data.

Impact Level: Application";

  tag_affected =
"AlienVault Open Source Security Information Management (OSSIM) version 4.3
and prior.";

  tag_solution =
"No solution or patch is available as of 17th October, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://www.alienvault.com/open-threat-exchange/projects";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/98052");
  script_xref(name : "URL" , value : "http://osvdb.org/ref/97/ossim-sql.txt");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/87652");
  script_summary("Check if AlienVault OSSIM is prone to sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ossim_web_detect.nasl");
  script_mandatory_keys("OSSIM/installed");
  script_require_ports("Services/www", 443);
  exit(0);
}


include("http_func.inc");
include("openvas-https.inc");
include("host_details.inc");

## Variable Initialization
http_port = "";
url = "";

## If the Version is not set in CPE get_app_port() won't work
## Get HTTP Port
http_port = get_http_port(default:443);
if(!http_port){
  http_port = 443;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Construct Malformed URL
url = "/RadarReport/radar-iso27001-potential.php?date_from='SQL-Injection-Test";

## Construct Attack Request
req = http_get(item: url, port: http_port);
res = https_req_get(port:http_port, request:req);

## Check the response to confirm vulnerability
if(res && res =~ "You have an error in your SQL syntax.*SQL-Injection-Test"
       && "datawarehouse.ssi_user" >< res)
{
  security_hole(http_port);
  exit(0);
}
