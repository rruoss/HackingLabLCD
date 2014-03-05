###############################################################################
# OpenVAS Vulnerability Test
# $Id: perforce_36261.nasl 15 2013-10-27 12:49:54Z jan $
#
# Perforce Multiple Unspecified Remote Security Vulnerabilities
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
tag_summary = "Perforce Server is prone to multiple unspecified remote security
vulnerabilities, including:

- Multiple unspecified denial-of-service vulnerabilities.
- An unspecified vulnerability.

An attacker can exploit these issues to crash the affected
application, denying service to legitimate users. Other attacks are
also possible.

Perforce 2008.1/160022 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(100269);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-07 09:47:24 +0200 (Mon, 07 Sep 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2010-0929");
 script_bugtraq_id(36261);
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Perforce Multiple Unspecified Remote Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36261");
 script_xref(name : "URL" , value : "http://www.perforce.com/perforce/products/p4d.html");
 script_xref(name : "URL" , value : "http://intevydis.com/company.shtml");

 script_description(desc);
 script_summary("Determine if perforce version is 2008.1/160022");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("perforce_detect.nasl");
 script_require_ports("Services/perforce", 1666);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/perforce");
if(!port)exit(0);
if (!get_tcp_port_state(port))exit(0);

if(!vers = get_kb_item(string("perforce/", port, "/version")))exit(0);
if(!isnull(vers)) {

  if(!version = split(vers, sep: "/", keep: 0))exit(0);
  if(version[2] >!< "2008.1")exit(0); 
  if(version_is_equal(version: version[3], test_version: "160022")) {
      security_warning(port:port);
      exit(0);
  }
}

exit(0);
