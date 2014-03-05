###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_42982.nasl 14 2013-10-27 12:33:37Z jan $
#
# Squid Proxy String Processing NULL Pointer Dereference Denial Of Service Vulnerability
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
tag_summary = "Squid is prone to a remote denial-of-service vulnerability caused by a
NULL pointer dereference.

An attacker can exploit this issue to cause the application to crash,
denying service to legitimate users. Due to the nature of the issue,
code execution may be possible; however, it has not been confirmed.

The issue affects the following versions:

Squid 3.0 to 3.0.STABLE25 Squid 3.1 to 3.1.7 Squid 3.2 to 3.2.0.1";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100789);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-07 15:26:31 +0200 (Tue, 07 Sep 2010)");
 script_bugtraq_id(42982);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-3072");
 script_name("Squid Proxy String Processing NULL Pointer Dereference Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42982");
 script_xref(name : "URL" , value : "http://www.squid-cache.org/");
 script_xref(name : "URL" , value : "http://www.squid-cache.org/Advisories/SQUID-2010_3.txt");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed squid version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_squid_detect.nasl");
 script_require_ports("Services/www","Services/http_proxy",3128,8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_kb_item("Services/http_proxy");

if(!port){
    exit(0);
}

if(!vers = get_kb_item(string("www/", port, "/Squid")))exit(0);

if(!isnull(vers)) {

  if(version_in_range(version:vers, test_version:"3.1", test_version2:"3.1.7") ||
     version_in_range(version:vers, test_version:"3.2", test_version2:"3.2.0.1")      ||
     version_in_range(version:vers, test_version:"3.0", test_version2:"3.0.STABLE25")) {

      security_warning(port:port);
      exit(0);
  
  } 
}

exit(0);
