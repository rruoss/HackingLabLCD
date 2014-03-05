# OpenVAS Vulnerability Test
# $Id: ser_register_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SIP Express Router Register Buffer Overflow
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote host is running a SIP Express Router.

A bug has been found in the remote device which may allow an attacker to
crash this device by sending a too long contact list in REGISTERs.";

tag_solution = "Upgrade to version 0.8.11 or use the patch provided at:
http://www.iptel.org/ser/security/secalert-002-0_8_10.patch

For additional details see: http://www.iptel.org/ser/security/";


if(description)
{
 script_id(11965);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "SIP Express Router Register Buffer Overflow";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "SER Register Buffer Overflow";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
 script_family("Buffer overflow");
 script_dependencies("sip_detection.nasl");
 script_require_ports(5060);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

banner = get_kb_item("sip/banner/5060");

if ( ! banner ) exit(0);

# Sample: Sip EXpress router (0.8.12 (i386/linux))

if (egrep(pattern:"Sip EXpress router .(0\.[0-7]\.|0\.8\.[0-9]|0\.8\.10) ", string:banner, icase:TRUE))
{
 security_warning(port:5060, protocol:"udp");
}
