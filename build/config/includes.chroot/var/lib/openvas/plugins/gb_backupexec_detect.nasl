###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_backupexec_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Symantec/Veritas BackupExec Detection
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
tag_summary = "Detection of Symantec/Veritas BackupExec.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103705";   

if (description)
{
 
 script_tag(name:"risk_factor", value:"None");
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"detection", value:"remote probe");
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-04-26 12:18:48 +0200 (Fri, 26 Apr 2013)");
 script_name("Symantec/Veritas BackupExec Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Symantec/Veritas BackupExec");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports(10000);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("byte_func.inc");
include("cpe.inc");
include("host_details.inc");

port = 10000;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp (port);
if(!soc)exit(0);

buf = recv(socket:soc, length:4);
if(isnull(buf))exit(0);

len = getword(blob:buf, pos:2);
buf = recv(socket:soc, length:len);
if(isnull(buf))exit(0);

if(ord(buf[15]) != 2 || ord(buf[14]) != 5)exit(0);

req = raw_string(0x80,0x00,0x00,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

send(socket:soc, data:req);
buf = recv(socket:soc, length:4);

if(strlen(buf) < 4) {
  close(soc);
  exit(0);
}  

len = getword(blob:buf, pos:2);
buf = recv(socket:soc, length:len);

if("VERITAS" >!< buf) {
  close(soc);
  exit(0);
}  

req = raw_string(0x80,0x00,0x00,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                 0x00,0x00,0xf3,0x1b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,
                 0x78,0x78,0x78,0x78,0x78,0x78,0x00,0x00);

send(socket:soc, data:req);
buf = recv(socket:soc, length:4);

if(strlen(buf) < 4) {
  close(soc);
  exit(0);
}  

len = getword(blob:buf, pos:2);
buf = recv(socket:soc, length:len);

if(strlen(buf) < 56) {
  close(soc);
  exit(0);
}  

pos = 40;

for(i=0; i<4; i++) {
  vers += getdword(blob:buf, pos:pos);
  if(i<3) vers +='.';
  pos = pos+4;
} 

close(soc);

set_kb_item(name:"BackupExec/Version", value:vers);

cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:symantec:veritas_backup_exec:");
if(isnull(cpe))
  cpe = 'cpe:/a:symantec:veritas_backup_exec';

register_product(cpe:cpe, location:port + '/tcp', nvt:SCRIPT_OID, port:port);  

log_message(data: build_detection_report(app:"Symantec/Veritas BackupExec", version:vers, install:port + '/tcp', cpe:cpe, concluded: 'Remote probe'),
            port:port);

exit(0);
