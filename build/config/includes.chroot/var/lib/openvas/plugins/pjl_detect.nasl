# OpenVAS Vulnerability Test
# $Id: pjl_detect.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Printer Job Language (PJL) Detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2007 Michel Arboi
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
tag_summary = "The remote service uses the PJL (Printer Job Language) protocol.

Description :

The remote service answered to a HP PJL request. 

This is indicates the remote device is probably a printer running JetDirect.

Through PJL, users can submit printing jobs, transfer files to or from 
the printers, change some settings, etc...";

  desc = "
  Summary:
  " + tag_summary;


if (description)
{
  script_id(80079);;
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name( "Printer Job Language (PJL) Detection");
  script_summary( "Talks PJL to HP JetDirect service"); 
 
  script_description( desc);
   script_category(ACT_GATHER_INFO);
  script_family( "Service detection");
  script_copyright("This script is Copyright (C) 2007 Michel Arboi");
  script_dependencies("find_service1.nasl");
  script_require_ports(9100, "Service/unknown");
  script_xref(name : "URL" , value : "http://www.maths.usyd.edu.au/u/psz/ps.html");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=bpl04568");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13208/bpl13208.pdf");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13207/bpl13207.pdf");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests)
{
 ports = get_kb_item("Service/unknown");
 ports = add_port_in_list(list: ports, port: 9100);
}
else
 ports = make_list(9100);

foreach port (ports)
 if ( get_port_state(port) && 
      service_is_unknown(port: port) &&
      # No banner for PJL, as far as I know
      strlen(get_unknown_banner(port: port, dontfetch: 1)) == 0 )
 {
  s = open_sock_tcp(port);
  if (s)
  {
   send(socket: s, data: '\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n');
   r = recv(socket: s, length: 1024);
   if (! isnull(r) && '@PJL INFO ID\r\n' >< r )
   {
    lines = split(r, keep: 0);
    if (max_index(lines) >= 1 && strlen(lines[1]) > 0)
      {
       info = ereg_replace(string: lines[1], pattern: '^ *"(.*)" *$', replace: "\1");
       if (strlen(info) == 0) info = lines[1];
       d = strcat(desc, '\n\nPlugin Output\n\nThe device INFO ID is:\n', info);
      }
    else
     d = desc;
    security_note(port: port, data: d);
    register_service(port: port, proto: 'jetdirect');
    set_kb_item(name: 'devices/hp_printer', value: TRUE);
   }
   close(s);
  }
 }
