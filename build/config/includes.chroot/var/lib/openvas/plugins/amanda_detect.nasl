# OpenVAS Vulnerability Test
# $Id: amanda_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Amanda client version
#
# Authors:
# Paul Ewing <ewing@ima.umn.edu>
#
# Copyright:
# Copyright (C) 2000 Paul J. Ewing Jr.
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
tag_summary = "This detects the Amanda backup system client
version. The client version gives potential attackers additional
information about the system they are attacking.";

if(description) {
    script_id(10462);
    script_version("$Revision: 17 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
    script_tag(name:"risk_factor", value:"None");

    name = "Amanda client version";
    script_name(name);
 
    desc = "
    Summary:
    " + tag_summary;

    script_description(desc);
 
    summary = "Detect Amanda client version";
    script_summary(summary);
 
    script_category(ACT_GATHER_INFO);
 
    script_copyright("This script is Copyright (C) 2000 Paul J. Ewing Jr.");
    family = "Service detection";
    script_family(family);
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

function get_version(soc, port, timeout)
{
  local_var result, temp, version, data;

    if ( ! isnull(timeout) )
     result = recv(socket:soc, length:2048, timeout:timeout);
   else
     result = recv(socket:soc, length:2048);

    if (result) {
        if (egrep(pattern:"^[^ ]+ [0-9]+\.[0-9]+", string:result)) {
	    temp = strstr(result, " ");
            temp = temp - " ";
            temp = strstr(temp, " ");
            version = result - temp;
            data = string("Amanda version: ", version);
            security_note(port:port, data:data, protocol:"udp");
            register_service(port:port, ipproto: "udp", proto:"amanda");
            set_kb_item(name:"Amanda/running", value:TRUE);
	}
    }
}

req = 'Amanda 2.3 REQ HANDLE 000-65637373 SEQ 954568800\nSERVICE ' + rand_str(length:8) + '\n';
soc1 = open_sock_udp(10080);
send(socket:soc1, data:req);
soc2 = open_sock_udp(10081);
send(socket:soc2, data:req);

get_version(soc:soc1, port:10080, timeout:NULL);
get_version(soc:soc2, port:10081, timeout:1);
