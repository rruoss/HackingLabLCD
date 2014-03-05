###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_zingiri_tickets_file_disc_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# WordPress Zingiri Tickets Plugin File Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to gain sensitive information.
  Impact Level: Application";
tag_affected = "WordPress Zingiri Tickets Plugin version 2.1.2";
tag_insight = "The flaw is due to insufficient permissions to the 'log.txt', which
  reveals administrative username and password hashes via direct http request.";
tag_solution = "No solution or patch is available as of 17th April, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/";
tag_summary = "This host is installed with WordPress Zingiri Tickets plugin and is prone to
  file disclosure vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802750";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-18 11:03:03 +0530 (Wed, 18 Apr 2012)");
  script_name("WordPress Zingiri Tickets Plugin File Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/111904/wpzingiritickets-disclose.txt");

  script_description(desc);
  script_summary("Check file disclosure vulnerability in WordPress Zingiri Tickets plugin");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Variable Initialization
port = "";
dir = "";
url = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct the attack req
url = string(dir, "/wp-content/plugins/zingiri-tickets/log.txt");

## Confirm exploit worked properly or not
if(http_vuln_check(port:port, url:url, pattern:"\[group_id\]",
                   extra_check:make_list("\[dept_id\]", "\[passwd\]",
                   "\[email\]"))){
  security_warning(port:port);
}
