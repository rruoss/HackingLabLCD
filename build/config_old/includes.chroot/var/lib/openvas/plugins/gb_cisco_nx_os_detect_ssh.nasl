###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_detect_ssh.nasl 18 2013-10-27 14:14:13Z jan $
#
# Cisco NX-OS Detection (SSH)
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103817";   
SCRIPT_DESC = "Cisco NX-OS Detection (SSH)";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"detection", value:"remote probe");
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-21 11:24:09 +0200 (Mon, 21 Oct 2013)");
 script_name(SCRIPT_DESC);

 tag_summary = "This script performs SSH based detection of Cisco NX-OS.";

  desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary("Checks for the presence of Cisco NX-OS");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("ssh_authorization.nasl","gb_cisco_nx_os_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_mandatory_keys("login/SSH/success");
 script_exclude_keys("cisco/nx_os/version"); # already detected by gb_cisco_nx_os_detect.nasl (snmp)

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }

 exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("cpe.inc");

if(get_kb_item("cisco/nx_os/version"))exit(0);

soc = ssh_login_or_reuse_connection();
if(!soc)exit(0);

show_ver = ssh_cmd_exec(cmd:'show ver\r\n');
close(soc);

if("Cisco Nexus Operating System (NX-OS) Software" >!< show_ver)exit(0);

version = eregmatch(pattern:"system:\s+version\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*", string: show_ver);

lines = split(show_ver, keep:FALSE);

foreach line (lines) {
  
  if("Chassis" >!< line)continue;
  mod = eregmatch(pattern:"(Nexus|cisco)\s(.*)\sChassis", string: line, icase:TRUE);
  break;

}  

if(!isnull(version[1])) {

  cpe = 'cpe:/o:cisco:nx-os:' + version[1];
  register_host_detail(name:"OS", value:cpe, nvt:SCRIPT_OID,desc:SCRIPT_DESC);
  
  set_kb_item(name:"cisco/nx_os/version", value: version[1]);
  set_kb_item(name:"Host/OS/SSH", value:"Cisco NX-OS");
  set_kb_item(name:"Host/OS/SSH/Confidence", value:100);

  log_message(data:'The remote host is running NX-OS ' + version[1] + '\nCPE: '+ cpe + '\nConcluded: ' + version[0] + '\n', port:0);

  if(!isnull(mod[2])) {
    set_kb_item(name:"cisco/nx_os/model", value: mod[2]);
    log_message(data:'The remote host is a Cisco ' + mod[2] + '\n', port:0);
  }  

}  

exit(0);
