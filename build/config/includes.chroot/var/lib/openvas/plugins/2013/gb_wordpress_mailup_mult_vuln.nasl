###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_mailup_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Wordpress MailUp Plugin Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitary HTML
  or web script via unspecified vectors in a user's browser session in context
  of an affected site and disclose sensitive information.
  Impact Level: Application";

tag_affected = "Wordpress MailUp Plugin version 1.3.1 and prior";
tag_insight = "Not properly restrict access to unspecified Ajax functions in
  ajax.functions.php";
tag_solution = "Upgrade Wordpress MailUp Plugin 1.3.2 or later,
  For updates refer to http://wordpress.org/extend/plugins/wp-mailup";
tag_summary = "This host is installed with Wordpress MailUp Plugin and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(803448);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-2640");
  script_bugtraq_id(58467);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-26 13:22:02 +0530 (Tue, 26 Mar 2013)");
  script_name("Wordpress MailUp Plugin Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/91274");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51917");
  script_xref(name : "URL" , value : "http://plugins.trac.wordpress.org/changeset?new=682420");
  script_xref(name : "URL" , value : "http://wordpress.org/extend/plugins/wp-mailup/changelog");

  script_description(desc);
  script_summary("Check if Wordpress MailUp Plugin is prone to path disclosure vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
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
include("http_keepalive.inc");

## Variable Initialization
url = "";
port = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
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
if(!dir = get_dir_from_kb(port:port, app:"WordPress")){
  exit(0);
}

## Construct the Attack Request
url = dir + "/wp-content/plugins/wp-mailup/ajax.functions.php?formData=save";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url,
        pattern:"<b>Fatal error</b>: .*ajax.functions.php"))
{
  security_warning(port);
  exit(0);
}
