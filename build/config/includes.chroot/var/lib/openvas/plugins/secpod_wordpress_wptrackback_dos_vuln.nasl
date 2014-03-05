###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_wptrackback_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# WordPress wp-trackback.php Denial of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to cause a Denial of Service
  due to high CPU consumption.
  Impact Level: System/Application";
tag_affected = "WordPress version prior to 2.8.5 on all platforms.";
tag_insight = "An error occurs in wp-trackbacks.php due to improper validation of user
  supplied data passed into 'mb_convert_encoding()' function. This can be
  exploited by sending multiple-source character encodings into the fuction.";
tag_solution = "Upgrade to WordPress version 2.8.5 or later.
  http://wordpress.org/download/";
tag_summary = "The host is running WordPress and is prone to Denial of Service
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900968";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3622");
  script_name("WordPress wp-trackback.php Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37088/");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9431");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53884");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2986");

  script_description(desc);
  script_summary("Check for the version of WordPress");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
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
  if(version_is_less(version:ver, test_version:"2.8.5")){
    security_warning(wpPort);
  }
}
