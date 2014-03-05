# OpenVAS Vulnerability Test
# $Id: vmware_server_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: VMware ESX/GSX Server detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote host appears to be running VMware ESX or GSX Server.

Description :

According to its banner, the remote host appears to be running a VMWare server authentication daemon, which likely indicates the remote host is running VMware ESX or GSX Server.";

if(description)
{
  script_id(20301);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("VMware ESX/GSX Server detection");
 
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
 
  summary = "Detect VMware Server Authentication Daemon";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 902);

  script_xref(name : "URL" , value : "http://www.vmware.com/");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

#the code
include("misc_func.inc");

if (thorough_tests) {
  port = get_kb_item("Services/unknown");
  if (!port) port = 902;
}
else port = 902;
if (!get_tcp_port_state(port)) exit(0);


banner = get_unknown_banner(port: port, dontfetch:0);
if (banner) {
  #220 VMware Authentication Daemon Version 1.00
  #220 VMware Authentication Daemon Version 1.10: SSL Required
  if ("VMware Authentication Daemon Version" >< banner) {
    register_service(port:port, ipproto:"tcp", proto:"vmware_auth_daemon");

    security_note(port);
  }
}
