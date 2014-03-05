###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bind_45134.nasl 14 2013-10-27 12:33:37Z jan $
#
# ISC BIND 'allow-query' Zone ACL Security Bypass Vulnerability
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
tag_summary = "ISC BIND is prone to a security-bypass vulnerability.

Successfully exploiting this issue allows remote attackers to
bypass zone-and-view Access Control Lists (ACLs) to perform
unintended queries.

Versions prior to BIND 9.7.2-P3 are vulnerable.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

if (description)
{
 script_id(100928);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-12-02 12:48:19 +0100 (Thu, 02 Dec 2010)");
 script_bugtraq_id(45134);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-3615");

 script_name("ISC BIND 'allow-query' Zone ACL Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45134");
 script_xref(name : "URL" , value : "http://www.isc.org/products/BIND/");
 script_xref(name : "URL" , value : "https://www.isc.org/software/bind/advisories/cve-2010-3615");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Bind version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
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

if(version =~ "^9\.7") {
  if(version_is_less(version:version, test_version:"9.7.2.P3")) {

      security_warning(port:53, proto:"udp");
      exit(0);

  }
}

exit(0);


