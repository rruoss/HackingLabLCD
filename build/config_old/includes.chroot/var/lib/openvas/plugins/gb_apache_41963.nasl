###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_41963.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apache HTTP Server Multiple Remote Denial of Service Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Apache HTTP Server is prone to multiple remote denial-of-service
vulnerabilities.

An attacker can exploit these issues to deny service to
legitimate users.

Versions prior to Apache 2.2.16 are vulnerable.";

tag_solution = "These issues have been fixed in Apache 2.2.16. Please see the
references for more information.";

if (description)
{
 script_id(100725);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-27 20:48:46 +0200 (Tue, 27 Jul 2010)");
 script_bugtraq_id(41963);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-1452");

 script_name("Apache HTTP Server Multiple Remote Denial of Service Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41963");
 script_xref(name : "URL" , value : "http://httpd.apache.org/download.cgi");
 script_xref(name : "URL" , value : "http://httpd.apache.org/");
 script_xref(name : "URL" , value : "http://www.apache.org/dist/httpd/Announcement2.2.html");
 script_xref(name : "URL" , value : "http://www.apache.org/dist/httpd/CHANGES_2.2.16");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Apache version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_apache_detect.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP.

httpdPort = get_http_port(default:80);
if(!httpdPort){
  exit(0);
}

httpdVer = get_kb_item("www/" + httpdPort + "/Apache");

if(httpdVer != NULL)
{
  if(version_in_range(version:httpdVer, test_version:"2.2", test_version2:"2.2.15")){
    security_warning(httpdPort);
    exit(0);
  }
}

exit(0);
