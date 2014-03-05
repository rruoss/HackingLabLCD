###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_42102.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apache 'mod_proxy_http' 2.2.9 for Unix Timeout Handling Information Disclosure Vulnerability
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
tag_summary = "Apache is prone to an information-disclosure vulnerability that
affects the 'mod_proxy_http' module.

Attackers can leverage this issue to gain access to sensitive
information that may aid in further attacks.

Apache 2.2.9 on Unix is vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100858);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-10-19 12:49:22 +0200 (Tue, 19 Oct 2010)");
 script_bugtraq_id(42102);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-2791");

 script_name("Apache 'mod_proxy_http' 2.2.9 for Unix Timeout Handling Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Apache version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("os_fingerprint.nasl","secpod_apache_detect.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42102");
 script_xref(name : "URL" , value : "http://httpd.apache.org/security/vulnerabilities_22.html");
 script_xref(name : "URL" , value : "http://httpd.apache.org/");
 script_xref(name : "URL" , value : "http://permalink.gmane.org/gmane.comp.security.oss.general/3243");
 script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=699841");
 script_xref(name : "URL" , value : "http://support.avaya.com/css/P8/documents/100109771");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");
include("host_details.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP.

if (host_runs("windows") != "no") {
  exit(0);
}


httpdPort = get_http_port(default:80);
if(!httpdPort){
  exit(0);
}

httpdVer = get_kb_item("www/" + httpdPort + "/Apache");

if(httpdVer != NULL)
{
  if(version_is_equal(version:httpdVer, test_version:"2.2.9")){
    security_warning(port:httpdPort);
    exit(0);
  }
}

exit(0);

