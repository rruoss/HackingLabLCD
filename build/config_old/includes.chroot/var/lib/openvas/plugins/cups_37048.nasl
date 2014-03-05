###############################################################################
# OpenVAS Vulnerability Test
# $Id: cups_37048.nasl 15 2013-10-27 12:49:54Z jan $
#
# CUPS File Descriptors Handling Remote Denial Of Service Vulnerability
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
tag_summary = "CUPS is prone to a denial-of-service vulnerability.

A remote attacker can exploit this issue to crash the affected
application, denying service to legitimate users.

This issue affects CUPS 1.3.7; other versions may be vulnerable as
well.";


tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100369);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-01 12:01:39 +0100 (Tue, 01 Dec 2009)");
 script_bugtraq_id(37048);
 script_cve_id("CVE-2009-3553");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("CUPS File Descriptors Handling Remote Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37048");
 script_xref(name : "URL" , value : "http://www.cups.org");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=530111");

 script_description(desc);
 script_summary("Determine if CUPS version is 1.3.7");
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
  if(version_is_equal(version:cupsVer, test_version:"1.3.7")){
    security_warning(cupsPort);
  }
}
