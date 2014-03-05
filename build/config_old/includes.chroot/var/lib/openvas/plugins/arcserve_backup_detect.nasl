###################################################################
# OpenVAS Vulnerability Test
#
# CA ARCServe Backup Detect
#
# LSS-NVT-2010-002
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

include("revisions-lib.inc");
tag_summary = "Remote host is running CA ARCServe Backup for Laptops and Desktops.";

# need description here to change it later
desc = "
 Summary:
 " + tag_summary;


if(description)
{
 script_id(102017);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-02 10:10:27 +0200 (Fri, 02 Apr 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("CA ARCServe Backup Detect");
 script_description(desc);
 script_summary("Detects CA ARCServe Backup for Laptops and Desktops on remote hosts");
 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright (C) 2010 LSS");
 script_family("Service detection");
 script_require_ports(1900);
 script_xref(name : "URL" , value : "http://arcserve.com/us/products/product.aspx?id=5282");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

port=1900;

# check for open port
if (!get_port_state(port)) exit(0);
 
soc = open_sock_tcp(port);
if (!soc) exit(0);

# Get server version
senddata = string("0000000019rxrGetServerVersion\n"); 
send(socket:soc, data:senddata);
r = recv_line(socket:soc, length:1000);

# extract version
match = eregmatch(pattern:"[0-9]+\.[0-9]+\.[0-9]+",string:r);

if(match) {
  set_kb_item(name:string("arcserve/", port, "/version"),value:match[0]);
  
  if(report_verbosity > 0) {
    info = "CA ARCServe Backup for Laptops and Desktops r" + match[0];
    info = '\n' + "The following version of CA ARCServe Backup for Laptops and Desktops is detected: "+'\n\n'+info;
    desc += info;
    security_note(port:port, data:desc);
  }
}

close(soc);
