###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_smtp.nasl 13 2013-10-27 12:16:33Z jan $
#
# SMTP STARTTLS Detection Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "The remote Mailserver supports the STARTTLS command.";

if (description)
{
 script_id(103118);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-11 13:29:22 +0100 (Fri, 11 Mar 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("SMTP STARTTLS Detection Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);

 script_summary("Checks for SMTP STARTTLS support");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

if(get_kb_item('SMTP/'+port+'/broken'))exit(0);
if(!get_port_state(port))exit(0);

encaps = get_kb_item("Transports/TCP/"+port);
if(encaps && encaps > ENCAPS_IP) exit(0);

if(!soc = smtp_open(port:port, helo:this_host()))exit(0);

send(socket:soc, data:string("STARTTLS\r\n"));
if(!r = smtp_recv_line(socket:soc))exit(0);

smtp_close(socket:soc);

if("220" >< r) {
  set_kb_item(name:string("smtp/",port,"/starttls"), value:TRUE);
  log_message(port:port);
  exit(0);
}
