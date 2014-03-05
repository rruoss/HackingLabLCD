###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_backupbuddy_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# WordPress Backupbuddy Multiple Vulnerabilities
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
tag_impact = "
  Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803884";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-2741", "CVE-2013-2742", "CVE-2013-2743", "CVE-2013-2744");
  script_bugtraq_id(58657, 58863, 58871, 58873);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-29 13:44:14 +0530 (Thu, 29 Aug 2013)");
  script_name("WordPress Backupbuddy Multiple Vulnerabilities");

  tag_summary =
"This host is installed with WordPress Backupbuddy plugin and is prone to
multiple vulnerabilities.";

  tag_vuldetect =
"Send a HTTP GET request and check whether it is able to disclose some
sensitive information or not.";

  tag_insight =
"Multiple flaws are due to,
- Fails to properly remove importbuddy.php during the final step of the backup
  process.
- Improper handling of input passed via 'step' parameter to importbuddy.php script.";

  tag_impact =
"Successful exploitation will allow attacker to bypass password authentication
and obtain potentially sensitive informations.";

  tag_affected =
"BackupBuddy plugin versions 1.3.4, 2.1.4, 2.2.4, 2.2.25, and 2.2.28";

  tag_solution =
"No solution or patch is available as of 29th August, 2013. Information
regarding this issue will be updated once the solution details are available.
For Updated refer to http://ithemes.com/purchase/backupbuddy";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/91631");
  script_xref(name : "URL" , value : "http://www.osvdb.com/91890");
  script_xref(name : "URL" , value : "http://www.osvdb.com/91891");
  script_xref(name : "URL" , value : "http://www.osvdb.com/91892");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120923");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Mar/206");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/backupbuddy-224-sensitive-data-exposure");
  script_summary("Check if WordPress Backupbuddy plugin is prone to security bypass vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
port = 0;
dir = "";
url = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Check for the plugin
req = http_get(item:string(dir,"/importbuddy.php"),  port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

## Confirm the plugin
if('>BackupBuddy' >< res && 'PluginBuddy.com<' >< res)
{
  ## Construct the crafted url
  url = dir + "/importbuddy.php?step=2";

  ## Try attack and check the response to confirm vulnerability.
  if(http_vuln_check(port:port, url:url,
                     pattern:"BackupBuddy Restoration & Migration Tool",
                     extra_check: make_list("Migrate to new server:",
                                            "Restore to same server")))
  {
    security_hole(port);
    exit(0);
  }
}
