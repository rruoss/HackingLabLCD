###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_foxypress_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# WordPress FoxyPress Plugin Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site, manipulate SQL queries by injecting arbitrary SQL code and to redirect
  users to arbitrary web sites and conduct phishing attacks.
  Impact Level: Application";
tag_affected = "WordPress FoxyPress Plugin Version 0.4.2.5 and prior";
tag_insight = "Inputs passed via the
  - 'xtStartDate', 'txtEndDate', and 'txtProductCod' parameters to edit.php,
  - 'id' parameter to foxypress-manage-emails.php,
  - 'status' and 'page' parameters to edit.php and
  - 'url' parameter to foxypress-affiliate.php are not properly sanitised
    before being returned to the user.";
tag_solution = "No solution or patch is available as of 02nd November, 2012. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/foxypress/";
tag_summary = "This host is running WordPress FoxyPress plugin and is prone to
  multiple vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803042";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-02 18:49:49 +0530 (Fri, 02 Nov 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("WordPress FoxyPress Plugin Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/86804");
  script_xref(name : "URL" , value : "http://www.osvdb.org/86818");
  script_xref(name : "URL" , value : "http://www.waraxe.us/content-95.html");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51109/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22374/");

  script_description(desc);
  script_summary("Check if WordPress FoxyPress Plugin is vulnerable to URL redirection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
url = "";
dir = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Construct attack
url = string(dir, "/wp-content/plugins/foxypress/foxypress-affiliate.php?url=" +
             "http://", get_host_name(), dir, "//index.php");

## Confirm exploit worked properly or not
sndReq = http_get(item:url, port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

## Check the response to confirm vulnerability
if(rcvRes &&  rcvRes =~ "HTTP/1.. 302 Found" &&
   egrep(pattern:'^Location:.*/index.php', string:rcvRes)){
  security_hole(port);
}
