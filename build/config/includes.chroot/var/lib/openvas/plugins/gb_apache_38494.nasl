###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_38494.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apache Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer
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
tag_summary = "Apache is prone to multiple vulnerabilities.

These issues may lead to information disclosure or other attacks.

Apache versions prior to 2.2.15 are affected.";

tag_solution = "Upgrade to  Apache 2.2.15 or Later.";

if (description)
{
 script_id(100514);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-04 12:28:05 +0100 (Thu, 04 Mar 2010)");
 script_bugtraq_id(38494,38491);
 script_cve_id("CVE-2010-0425","CVE-2010-0434","CVE-2010-0408","CVE-2007-6750");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 script_name("Apache Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determine if installed Apache version is <= 2.2.14");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_apache_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys('apache/installed'); # key is only present if report_paranoia is > 1
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38494");
 script_xref(name : "URL" , value : "http://httpd.apache.org/security/vulnerabilities_22.html");
 script_xref(name : "URL" , value : "http://httpd.apache.org/");
 script_xref(name : "URL" , value : "https://issues.apache.org/bugzilla/show_bug.cgi?id=48359");
 script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=917870");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

httpdPort = get_http_port(default:80);
if(!httpdPort){
  exit(0);
}

version = get_kb_item("www/" + httpdPort + "/Apache");

if(version != NULL){
  if(version_in_range(version:version, test_version: "2.2",test_version2:"2.2.14")){
    security_hole(port: httpdPort);
    exit(0);
  }
}

exit(0);
