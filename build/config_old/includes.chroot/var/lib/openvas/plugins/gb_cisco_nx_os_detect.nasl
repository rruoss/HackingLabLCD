###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Cisco NX-OS Detection
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103799";   
SCRIPT_DESC = "Cisco NX-OS Detection";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"detection", value:"remote probe");
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-09 16:24:09 +0200 (Wed, 09 Oct 2013)");
 script_name(SCRIPT_DESC);

 tag_summary = "This script performs SNMP based detection of Cisco NX-OS.";

  desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary("Checks for the presence of Cisco NX-OS");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_snmp_sysdesc.nasl");
 script_require_udp_ports("Services/snmp", 161);
 script_require_keys("SNMP/sysdesc");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }

 exit(0);
}

include("dump.inc");
include("host_details.inc");
include("cpe.inc");

function parse_result(data) {

  if(strlen(data) < 8) return FALSE;

  for(v=0; v < strlen(data); v++) {
      if(ord(data[v]) == 43 && ord(data[v-1]) == 13) {
        ok = TRUE;
        break;
      }
      oid_len = ord(data[v]);
  }

  if(!ok || oid_len < 8)return FALSE;

  tmp = substr(data,(v+oid_len+2));

  if (!isprint (c:tmp[0])) {
    tmp = substr(tmp,1,strlen(tmp)-1);
  }

  return tmp;

}

port = get_kb_item("Services/snmp");
if(!port)port = 161;

if(!(get_udp_port_state(port)))exit(0);

# Example:
# Cisco NX-OS(tm) n7000, Software (n7000-s1-dk9), Version 5.2(3a), RELEASE SOFTWARE Copyright (c) 2002-2011 by Cisco Systems, Inc. Compiled 12/15/2011 12:00:00;
# Cisco NX-OS(tm) ucs, Software (ucs-6100-k9-system), Version 5.0(3)N2(2.04b), RELEASE SOFTWARE Copyright (c) 2002-2012 by Cisco Systems, Inc. Compiled 10/21/2012 11:00:00
sysdesc = get_kb_item("SNMP/sysdesc");
if(!sysdesc)exit(0);

if("Cisco NX-OS" >!< sysdesc)exit(0);

nx_version = eregmatch(pattern:"Version ([^,]+),", string:sysdesc);
if(isnull(nx_version[1]))exit(0);

nx_ver = nx_version[1];
cpe = 'cpe:/o:cisco:nx-os:' + nx_ver;

register_host_detail(name:"OS", value:cpe, nvt:SCRIPT_OID,desc:SCRIPT_DESC);
register_host_detail(name:"OS", value:"NX-OS", nvt:SCRIPT_OID,desc:SCRIPT_DESC);

set_kb_item(name:"cisco/nx_os/version", value: nx_ver);

set_kb_item(name:"Host/OS/SNMP", value:"Cisco NX-OS");
set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

log_message(data:'The remote host is running NX-OS ' + nx_ver + '\nCPE: '+ cpe + '\nConcluded: ' + sysdesc + '\n', port:0);

community = get_kb_item("SNMP/community");
if(!community)community = "public";

SNMP_BASE = 40;
COMMUNITY_SIZE = strlen(community);
sz = COMMUNITY_SIZE % 256;

len = SNMP_BASE + COMMUNITY_SIZE;

for (i=0; i<3; i++) {

  soc = open_sock_udp(port);
  if(!soc)exit(0);

  # snmpget -v<version> -c <community> <host> 1.3.6.1.2.1.47.1.1.1.1.2.149
  sendata = raw_string(0x30,len,0x02,0x01,i,0x04,sz) + 
            community + 
            raw_string(0xa0,0x21,0x02,0x04,0x7f,0x45,0x71,0x96,
                       0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x13,
                       0x30,0x11,0x06,0x0d,0x2b,0x06,0x01,0x02,
                       0x01,0x2f,0x01,0x01,0x01,0x01,0x02,0x81,
                       0x15,0x05,0x00);

  send(socket:soc, data:sendata);
  result = recv(socket:soc, length:400, timeout:1);
  close(soc);

  if(!result || ord(result[0]) != 48)continue;

  # Nexus7000 C7010 (10 Slot) Chassis
  # UCS 6100 Series Fabric Interconnect;
  if(!res = parse_result(data:result))continue;

  set_kb_item(name:"cisco/nx_os/model", value: res);
  log_message(data:'The remote host is a Cisco ' + res + '\n', port:0);
  exit(0);

}

exit(0);
