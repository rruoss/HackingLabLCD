###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_mult_vuln_may09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Wordpress Multiple Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_impact = "Attackers can exploit this issue to causes denial of service or to redirect
  the URL to any malicious website and conduct phishing attacks.
  Impact Level: Application";
tag_affected = "Wordpress version 2.6.x";
tag_insight = "Multiple flaws are due to lack of sanitization in user supplied data which
  can be exploited through 'wp-admin/upgrade.php' via a direct request and
  'wp-admin/upgrade.php' via a URL in the backto parameter.";
tag_solution = "Upgrade your wordpress to the latest version 2.7.1
  http://wordpress.org";
tag_summary = "This host has Wordpress installed and is prone to Multiple
  Vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800704";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-6767", "CVE-2008-6762");
  script_name("Wordpress Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/52213");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2008-12/0226.html");

  script_description(desc);
  script_summary("Check for the version of Wordpress");
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


include("version_func.inc");
include("http_func.inc");
include("host_details.inc");


wordpressPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!wordpressPort){
  exit(0);
}

if(!get_port_state(wordpressPort)){
  exit(0);
}

if(!version = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(version_in_range(version:version, test_version:"2.6", test_version2:"2.6.3")){
  security_hole(wordpressPort);
}
