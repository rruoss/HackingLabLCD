###############################################################################
# OpenVAS Vulnerability Test
# $Id: novell_imanager_37672.nasl 14 2013-10-27 12:33:37Z jan $
#
# Novell iManager Importing/Exporting Schema Stack Buffer Overflow Vulnerability
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
tag_summary = "Novell iManager is prone to a stack-based buffer-overflow
vulnerability because it fails to perform adequate boundary checks on
user-supplied data.

Attackers may exploit this issue to execute arbitrary code in the
context of the affected application. Failed exploit attempts will
likely cause denial-of-service conditions.

Novell iManager 2.7.2 and prior are vulnerable.";

tag_solution = "The vendor has released an advisory and fixes. Please see the
references for details.";

if (description)
{
 script_id(100435);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-11 11:18:50 +0100 (Mon, 11 Jan 2010)");
 script_bugtraq_id(37672);
 script_cve_id("CVE-2009-4486");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Novell iManager Importing/Exporting Schema Stack Buffer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determine if Novell iManager version is < 2.7.2");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("novell_imanager_detect.nasl");
 script_require_ports("Services/www", 8080, 8443);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37672");
 script_xref(name : "URL" , value : "http://www.novell.com/products/consoles/imanager/features.html");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-001/");
 script_xref(name : "URL" , value : "http://www.novell.com/support/viewContent.do?externalId=7004985&amp;sliceId=1");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("www/", port, "/imanager")))exit(0);

if(!isnull(version) && version >!< "unknown") {

  if(version_is_less(version: vers, test_version: "2.7.2")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
