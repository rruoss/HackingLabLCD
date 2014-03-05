###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_imanager_2_7_4.nasl 14 2013-10-27 12:33:37Z jan $
#
# Novell iManager < 2.7.4 Multiple Vulnerabilities
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
tag_summary = "Novell iManager is prone to multiple Vulnerabilities.

1.
A stack-based buffer-overflow vulnerability because it fails to
perform adequate boundary checks on user-supplied data.

Attackers may exploit this issue to execute arbitrary code with SYSTEM-
level privileges. Successful exploits will completely compromise
affected computers. Failed exploit attempts will result in a denial-of-
service condition.

2.
A denial-of-service vulnerability due to an off-by-one error.

Attackers may exploit this issue to crash the affected application,
denying service to legitimate users.

Versions prior to Novell iManager 2.7.4 are vulnerable.";


if (description)
{
 script_id(100692);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-24 12:53:20 +0200 (Thu, 24 Jun 2010)");
 script_bugtraq_id(40480,40485);
 script_cve_id("CVE-2010-1929","CVE-2010-1930");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Novell iManager < 2.7.4 Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40480");
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40485");
 script_xref(name : "URL" , value : "http://www.coresecurity.com/content/novell-imanager-buffer-overflow-off-by-one-vulnerabilities");
 script_xref(name : "URL" , value : "http://www.novell.com/products/consoles/imanager/features.html");

 script_description(desc);
 script_summary("Determine if Novell iManager version is < 2.7.4");
 script_category(ACT_GATHER_INFO);
 script_family("Buffer overflow");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("novell_imanager_detect.nasl");
 script_require_ports("Services/www", 8080, 8443);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("www/", port, "/imanager")))exit(0);

if(!isnull(version) && version >!< "unknown") {

  if(version_is_less(version: vers, test_version: "2.7.4")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
