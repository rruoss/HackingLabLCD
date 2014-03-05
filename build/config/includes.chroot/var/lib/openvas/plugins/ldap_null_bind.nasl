# OpenVAS Vulnerability Test
# $Id: ldap_null_bind.nasl 17 2013-10-27 14:01:43Z jan $
# Description: LDAP allows anonymous binds
#
# Authors:
# John Lampe (j_lampe@bellsouth.net)
#
# Copyright:
# Copyright (C) 2000 John Lampe....j_lampe@bellsouth.net
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
tag_summary = "It is possible to disclose LDAP information.

Description :

Improperly configured LDAP servers will allow any user to connect to the
server via a NULL BIND and query for information.

NULL BIND is required for LDAPv3. Therefore this Plugin will not run
against LDAPv3 servers.";

tag_solution = "Disable NULL BIND on your LDAP server";

if(description)
{
  script_id(10723);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("LDAP allows anonymous binds");
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
  script_summary("Check for LDAP null bind");
  script_category(ACT_GATHER_INFO);
  script_family("Remote file access");
  script_copyright("Copyright (C) 2000 John Lampe....j_lampe@bellsouth.net");

  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("ldap.inc");

#
# The script code starts here


function send_stuff (myport) {
    soc = open_sock_tcp(myport);
    if (!soc) {
        return(0);
    }
    send(socket:soc, data:string);
    rez = recv(socket:soc, length:4096);
    close(soc);
    return(rez);
}


port = get_kb_item("Services/ldap");
if (!port) port = 389;

string = raw_string (0x30,0x0C,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x02,0x04,0x00,0x80,0x80);

if (get_port_state(port)) {

    if(is_ldapv3(port:port))exit(0);

    result1 = send_stuff(myport:port);
    if(result1)
    {
      error_code = substr(result1, strlen(result1) - 7, strlen(result1) - 5);
      if (hexstr(error_code) == "0a0100") {
        security_warning(port);
        set_kb_item(name: string("LDAP/", port, "/NULL_BIND"), value:  TRUE);
        exit(0);
      }
    }
}
