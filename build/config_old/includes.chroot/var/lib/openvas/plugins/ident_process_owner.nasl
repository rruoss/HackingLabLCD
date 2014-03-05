# OpenVAS Vulnerability Test
# $Id: ident_process_owner.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Identd scan
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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
tag_summary = "This plugin uses identd (RFC 1413) to determine which user is 
running each service";

if(description)
{
 script_id(14674);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 script_name( "Identd scan");
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Get UIDs with identd";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 family = "Service detection";
 script_family(family);
 script_dependencies("find_service1.nasl", "slident.nasl");
 script_require_ports("Services/auth", 113);
 #script_exclude_keys("Host/ident_scanned");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");
include('global_settings.inc');

#if (get_kb_item("Host/ident_scanned")) exit(0);

ports = get_kb_list("Ports/tcp/*");
if(isnull(ports))
  if (COMMAND_LINE)
   for (i = 1; i <= 65535; i ++)
    ports[i] = "Ports/tcp/"+i;
  else
   exit(0);

# Should we only use the first found identd?

list = get_kb_list("Services/auth");
if ( ! isnull(list) ) 
     list = make_list(113, list);
else 
     list = make_list(113);

foreach iport ( list )
{
 if (get_port_state(iport) && ! get_kb_item('fake_identd/'+iport))
 {
  isoc = open_sock_tcp(iport);
  if (isoc) break;
 }
 else
  debug_print('Port ', iport, ' is closed or blacklisted\n');
}
if (! isoc) exit(0);
debug_print('iport=', iport, '\n');

# Try several times, as some ident daemons limit the throughput of answers?!
for (i = 1; i <= 6 && ! isnull(ports); i ++)
{
 prev_ident_n = identd_n;
 j = 0;
 if (i > 1) debug_print('Pass #', i);
foreach port (keys(ports))
{
 port = int(port - "Ports/tcp/");
 if (get_port_state(port) && ! get_kb_item("Ident/tcp"+port))
 {
  soc = open_sock_tcp(port);
  if (soc)
  {
   debug_print('Testing ', port, '\n');
   req = strcat(port, ',', get_source_port(soc), '\r\n');
   if (send(socket: isoc, data: req) <= 0)
   {
# In case identd does not allow several requests in a raw
    close(isoc);
    isoc = open_sock_tcp(iport);
    if (!isoc) { close(soc); exit(0); }
    send(socket: isoc, data: req);
   }
   id = recv_line(socket: isoc, length: 1024);
   debug_print('Identd(',port,')=', id);
   if (id)
   {
    ids = split(id, sep: ':');
    if ("USERID" >< ids[1] && strlen(ids[3]) < 30 )
    {
     identd_n ++;
     set_kb_item(name: "Ident/tcp/"+port, value: ids[3]);
     security_note(port: port, 
data: 'identd reveals that this service is running as user '+ids[3]);
    }
    else
     bad[j++] = port;
   }
   else
    bad[j++] = port;
  }
 }
}
 # Exit if we are running in circles
 if (prev_ident_n == identd_n) break;
 ports = NULL;
 foreach j (bad) ports[j] = j;
 bad = NULL;
}
if (-- i > 1) debug_print(i, ' passes were necessary');

close(isoc);
set_kb_item(name: "Host/ident_scanned", value: TRUE);

