###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Find and list USB-Storage Modules, list pluged USB-Storage Devices.
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
#
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This plugin uses ssh to find and list USB-Storage Modules, list pluged USB-Storage Devices..";

if(description)
{
  script_id(96086);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Mon May 10 16:35:52 2010 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Find and list USB-Storage Modules, list pluged USB-Storage Devices.");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Find and list USB-Storage Modules, list pluged USB-Storage Devices.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("find_service.nasl", "ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

cmdline = 0;
include("ssh_func.inc");

port = get_preference("auth_port_ssh");
if(!port) port = get_kb_item("Services/ssh");
if(!port) {
    port = 22;
}
sock = ssh_login_or_reuse_connection();
if(!sock) {
    error = get_ssh_error();
    if (!error) error = "No SSH Port or Connection!";
    log_message(port:port, data:error);
    set_kb_item(name: "GSHB/usbmodules", value:"error"); 
    set_kb_item(name: "GSHB/usbstorage", value:"error");
    set_kb_item(name: "GSHB/usbbus", value:"error");
    set_kb_item(name: "GSHB/usbmodules/log", value:error);
    exit(0);
}

uname = ssh_cmd(socket:sock, cmd:"uname -a");
if (uname !~ "SunOS .*"){
  usbmodules = ssh_cmd(socket:sock, cmd:"find /lib/modules/ | grep -i usb-storage.ko");
  usbstorage = ssh_cmd(socket:sock, cmd:"cat /sys/kernel/debug/usb/devices | grep -i -A2 -B5 usb-storage");
  usbbus = ssh_cmd(socket:sock, cmd:"find /sys/bus/ | grep -i usb-storage");
}
else if(uname =~ "SunOS .*"){
  usbmodules = ssh_cmd(socket:sock, cmd:"/usr/sbin/modinfo|grep -i usb");
  usbstorage = ssh_cmd(socket:sock, cmd:"rmformat -l");
  if (usbstorage !~ ".*Bus: USB.*") usbstorage = "none";
  usbbus = "none";
}

if ("FIND: Invalid switch" >< usbmodules|| "FIND: Parameterformat falsch" >< usbmodules){
  set_kb_item(name: "GSHB/usbbus", value:"windows");
  set_kb_item(name: "GSHB/usbmodules", value:"windows");
  set_kb_item(name: "GSHB/usbstorage", value:"windows"); 
  exit(0);
}

if (usbstorage =~ ".*Datei oder Verzeichnis nicht gefunden.*" ||  usbstorage =~ ".*No such file or directory.*" || usbstorage =~ "cat: .* /sys/kernel/debug/usb/devices:.*") usbstorage = "none";
if (usbmodules =~ ".*Datei oder Verzeichnis nicht gefunden.*" ||  usbmodules =~ ".*No such file or directory.*" ) usbmodules = "none";
if (usbbus =~ ".*Datei oder Verzeichnis nicht gefunden.*" ||  usbbus =~ ".*No such file or directory.*" ) usbbus = "none";
if (!usbmodules) usbmodules = "none";
if (!usbstorage) usbstorage = "none";
if (!usbbus) usbbus = "none";

set_kb_item(name: "GSHB/usbbus", value:usbbus);
set_kb_item(name: "GSHB/usbmodules", value:usbmodules);
set_kb_item(name: "GSHB/usbstorage", value:usbstorage); 
exit(0);

