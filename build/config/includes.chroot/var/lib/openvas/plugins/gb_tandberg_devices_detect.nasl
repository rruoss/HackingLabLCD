###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tandberg_devices_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Tandberg Devices Detection
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
tag_summary = "Detection of Tandberg Devices.
                    
The script sends a connection request to the server and attempts to
determine if the remote host is a Tandberg device and extract the codec release from
the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103694";   

if (description)
{
 
 script_tag(name:"risk_factor", value:"None");
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-04-11 09:34:17 +0200 (Thu, 11 Apr 2013)");
 script_name("Tandberg Devices Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Tandberg Devices");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("telnetserver_detect_type_nd_version.nasl");
 script_require_ports(23);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("telnet_func.inc");
include("host_details.inc");

port = 23;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

buf = telnet_negotiate(socket:soc);
close(soc);

if("TANDBERG Codec Release" >!< buf)exit(0);

vers = string("unknown");
install = port + '/tcp';

version = eregmatch(string: buf, pattern:string("TANDBERG Codec Release ([^\r\n]+)"),icase:TRUE);
if(!isnull(version[1])) vers = version[1];

set_kb_item(name:"host_is_tandberg_device",value:TRUE);
set_kb_item(name:"tandberg_codec_release", value:vers);
cpe = 'cpe:/h:tandberg'; # we don't know which device exactly it is, so just set the base cpe

register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

message = 'The remote Host is a Tandberg Device.\nCodec Release: ' + vers + '\nCPE: ' + cpe + '\nConcluded: ' + buf + '\n';

log_message(data:message, port:port);

exit(0);