###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firebird_default_credentials.nasl 14 2013-10-27 12:33:37Z jan $
#
# Firebird Default Credentials
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
tag_summary = "It is possible to connect to the remote database service using default
credentials.

The remote Firebird Server uses default credentials (SYSDBA/masterkey). An attacker
may use this flaw to execute commands against the remote host, as well as read your
database content.";

tag_solution = "Change the default password by using the gsec management tool.";

if (description)
{
 
 script_tag(name:"risk_factor", value:"Critical");
 script_id(100792);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-08 15:41:05 +0200 (Wed, 08 Sep 2010)");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");


desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_name("Firebird Default Credentials");
 script_description(desc);
 script_summary("Checks if it is possible to connect to the remote database service using default credentials");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("remote-detect-firebird.nasl");
 script_require_ports("Services/gds_db", 3050);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.firebirdsql.org/manual/qsg2-config.html#qsg2-config-security");
 exit(0);
}

port = get_kb_item("Services/gds_db");
if(!port)port = 3050;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

firebird_auth_packet   = raw_string(
0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x13,0x00,0x00,0x00,0x02,0x00,
0x00,0x00,0x24,0x00,0x00,0x00,0x1c,0x2f,0x6f,0x70,0x74,0x2f,0x66,
0x69,0x72,0x65,0x62,0x69,0x72,0x64,0x2f,0x62,0x69,0x6e,0x2f,0x6c,
0x65,0x67,0x69,0x6f,0x6e,0x2e,0x66,0x64,0x62,0x00,0x00,0x00,0x02,
0x00,0x00,0x00,0x17,0x01,0x04,0x72,0x6f,0x6f,0x74,0x04,0x09,0x63,
0x68,0x72,0x69,0x73,0x74,0x69,0x61,0x6e,0x05,0x04,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
0x02,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x0a,
0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x03,0x00,
0x00,0x00,0x04);

send(socket:soc, data:firebird_auth_packet);
response = recv(socket:soc, length:1024);

if(!isnull(response) && strlen(response) == 16 && "030000000a0000000100000003" >< hexstr(response)) {

  p = raw_string(
                 0x00,0x00,0x00,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x20,0x00,0x00,0x00,
                 0x00,0x00,0x00,0x14,0x01,0x1c,0x06,0x53,0x59,0x53,0x44,0x42,0x41,0x1d,0x09,0x6d,
                 0x61,0x73,0x74,0x65,0x72,0x6b,0x65,0x79);

  send(socket:soc, data:p);
  r = recv(socket:soc, length:1024);
  close(soc);

  if(strlen(r) >= 16 && "CreateFile" >< r) {
    security_hole(port:port);
    exit(0);
  }

}

exit(0);