##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_support_incident_tracker_mult_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Support Incident Tracker SiT! Multiple SQL Injection Vulnerabilities
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
tag_impact = "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application.";
tag_affected = "Support Incident Tracker version prior 3.63p1 and prior.";

tag_insight = "The flaws are due to improper input validation in 'tasks.php',
  'report_marketing.php', 'search.php' and 'billable_incidents.php' scripts
  via various parameters before being used in a SQL query.";
tag_solution = "Upgrade to Support Incident Tracker SiT! version 3.64 or later
  For updates refer to http://sitracker.org/";
tag_summary = "This host is running Support Incident Tracker and is prone to SQL
  injection vulnerabilities.";

if(description)
{
  script_id(902703);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_bugtraq_id(48896);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Support Incident Tracker SiT! Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/518999");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103442/PT-2011-25.txt");

  script_description(desc);
  script_summary("Check for the version of Support Incident Tracker");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("support_incident_tracker_detect.nasl");
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

## Get HTTP port
sitPort = get_http_port(default:80);
if(!sitPort){
  exit(0);
}

## Get version
sitVer = get_version_from_kb(port:sitPort, app:"support_incident_tracker");
if(!sitVer){
  exit(0);
}

## Check for SIT version
if(version_is_less_equal(version:sitVer, test_version:"3.63.p1")){
  security_hole(sitPort);
}
