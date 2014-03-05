###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipmi_md2_enabled.nasl 79 2013-11-26 14:44:32Z mime $
#
# IPMI MD2 Auth Type Support Enabled
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

tag_summary = "IPMI MD2 auth type support is enabled on the remote host.";
tag_solution = "Disable MD2 auth type support.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103839";  

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 79 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-26 15:44:32 +0100 (Tue, 26 Nov 2013) $");
 script_tag(name:"creation_date", value:"2013-11-26 12:33:03 +0100 (Tue, 26 Nov 2013)");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("IPMI MD2 Auth Type Support Enabled");
 script_description(desc);
 script_summary("Check if MD2 auth type support is enabled.");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_ipmi_detect.nasl");
 script_require_udp_ports("Services/udp/ipmi", 623);
 script_mandatory_keys("ipmi/md2_supported");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }

 exit(0);
}

port = get_kb_item("Services/udp/ipmi");
if(!port)exit(0);

if(!get_udp_port_state(port))exit(0);

if(get_kb_item("ipmi/md2_supported")) {
  security_hole(port:port, proto:"udp");
  exit(0);
}   

exit(99);

