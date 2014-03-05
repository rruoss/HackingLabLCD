###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_php_code_exec_vuln_900183.nasl 16 2013-10-27 13:09:52Z jan $
#
# WordPress 'wp-admin/options.php' Remote Code Execution Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code by
  uploading a PHP script and adding this script pathname to active_plugins.
  Impact Level: System/Application";
tag_affected = "WordPress, WordPress prior to 2.3.3
  WordPress, WordPress MU prior to 1.3.2";
tag_insight = "The flaw is due to error under 'wp-admin/options.php' file. These
  can be exploited by using valid user credentials with 'manage_options' and
  upload_files capabilities.";
tag_solution = "Upgrade to version 1.3.2 and 2.3.3 or later
  http://mu.wordpress.org/download/";
tag_summary = "The host is running WordPress and is prone to Remote Code
  Execution vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900183";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-5695");
  script_bugtraq_id(27633);
  script_name("WordPress 'wp-admin/options.php' Remote Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28789");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/5066");
  script_xref(name : "URL" , value : "http://mu.wordpress.org/forums/topic.php?id=7534&amp;page&amp;replies=1");

  script_description(desc);
  script_summary("Check for the Version of WordPress");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
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


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");


wpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!wpPort){
  exit(0);
}


if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:wpPort))exit(0);


if(ver != NULL)
{
  # Grep for version 2.3.2 and prior
  if(version_is_less_equal(version:ver, test_version:"2.3.2")){
    security_hole(wpPort);
  }
}
