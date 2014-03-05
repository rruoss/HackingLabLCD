###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bind_43573.nasl 14 2013-10-27 12:33:37Z jan $
#
# ISC BIND Denial Of Service and Security Bypass Vulnerability
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
tag_summary = "ISC BIND is prone to a security-bypass vulnerability and a denial-of-
service vulnerability.

Successfully exploiting these issues allows remote attackers to crash
affected DNS servers, denying further service to legitimate users,
bypass certain security restrictions and perform unauthorized actions.
Other attacks are also possible.

ISC BIND versions 9.7.2 through 9.7.2-P1 are vulnerable.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

if (description)
{
 script_id(100831);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-30 13:18:50 +0200 (Thu, 30 Sep 2010)");
 script_bugtraq_id(43573);
 script_cve_id("CVE-2010-0218", "CVE-2010-3762");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("ISC BIND Denial Of Service and Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43573");
 script_xref(name : "URL" , value : "http://ftp.isc.org/isc/bind9/9.7.2-P2/RELEASE-NOTES-BIND-9.7.2-P2.html");
 script_xref(name : "URL" , value : "https://lists.isc.org/pipermail/bind-announce/2010-September/000655.html");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Bind version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("dns_server.nasl","bind_version.nasl");
 script_require_ports("Services/dns", 53);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");
include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

if(!get_kb_item("DNS/tcp/53"))exit(0);
if(!version = get_kb_item("bind/version"))exit(0);
version = str_replace(find:"-", string: version, replace:".");

if(version =~ "^9\.7\.2") {
  if(version_is_less(version:version, test_version:"9.7.2.P2")) {

      security_warning(port:53, proto:"udp");
      exit(0);

  }
}

exit(0);

