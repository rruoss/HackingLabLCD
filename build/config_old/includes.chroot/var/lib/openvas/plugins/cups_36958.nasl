###############################################################################
# OpenVAS Vulnerability Test
# $Id: cups_36958.nasl 15 2013-10-27 12:49:54Z jan $
#
# CUPS 'kerberos' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "CUPS is prone to a cross-site scripting vulnerability because the
application fails to sufficiently sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks.

Note: This vulnerability was originally reported in BID 36956 (Apple
      Mac OS X 2009-006 Multiple Security Vulnerabilities), but has
      been given its own record to better document it.

This issue affects CUPS versions prior to 1.4.2.";


tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100344);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-13 12:21:24 +0100 (Fri, 13 Nov 2009)");
 script_bugtraq_id(36958);
 script_cve_id("CVE-2009-2820");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("CUPS 'kerberos' Parameter Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36958");
 script_xref(name : "URL" , value : "http://www.cups.org/articles.php?L590");
 script_xref(name : "URL" , value : "http://www.cups.org");
 script_xref(name : "URL" , value : "http://www.cups.org/str.php?L3367");
 script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-271169-1");

 script_description(desc);
 script_summary("Determine if Cups version is < 1.4.2");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("secpod_cups_detect.nasl");
 script_require_ports("Services/www", 631);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

cupsPort = get_http_port(default:631);
if(!cupsPort){
  exit(0);
}

cupsVer = get_kb_item("www/"+ cupsPort + "/CUPS");
if(!cupsVer){
  exit(0);
}

if(cupsVer != NULL)
{
  # Check for CUPS version < 1.4.2
  if(version_is_less(version:cupsVer, test_version:"1.4.2")){
    security_warning(cupsPort);
  }
}
