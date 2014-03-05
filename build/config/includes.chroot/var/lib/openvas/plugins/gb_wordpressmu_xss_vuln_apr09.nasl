###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpressmu_xss_vuln_apr09.nasl 15 2013-10-27 12:49:54Z jan $
#
# WordPress MU Cross-Site Scripting Vulnerability - Apr09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let the attacker execute malicious crafted
  HTTP headers and conduct cross site scripting attacks to gain administrative
  privileges into the affected web application.
  Impact Level: Application";
tag_affected = "WordPress MU before 2.7 on all running platform.";
tag_insight = "The vulnerability is due to improper validation of user supplied input in
  'wp-includes/wpmu-functions.php' for choose_primary_blog function.";
tag_solution = "Update to Version 2.7
  http://mu.wordpress.org/download";
tag_summary = "The host is running WordPress MU and is prone to Cross-Site
  Scripting Vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800376";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1030");
  script_bugtraq_id(34075);
  script_name("WordPress MU Cross-Site Scripting Vulnerability - Apr09");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8196");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49184");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Mar/1021838.html");

  script_description(desc);
  script_summary("Check for the Version of WordPress MU");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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


wpmuPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!wpmuPort){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(ver != NULL)
{
  if(version_is_less(version:ver, test_version:"2.7")){
    security_warning(port:wpmuPort);
  }
}
