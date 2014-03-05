###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_esx_snmp_detect.nasl 65 2013-11-14 11:18:55Z mime $
#
# VMware ESX detection (SNMP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
tag_summary = "This host is running VMware ESX(i).";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103417";

if (description)
{
 
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 65 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-14 12:18:55 +0100 (Do, 14. Nov 2013) $");
 script_tag(name:"creation_date", value:"2012-02-14 10:38:50 +0100 (Tue, 14 Feb 2012)");
 script_name("VMware ESX detection (SNMP)");
 script_description(desc);
 script_summary("Checks for the presence of VMware ESX (SNMP)");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_snmp_sysdesc.nasl");
 script_require_udp_ports("Services/snmp", 161);
 script_require_keys("SNMP/sysdesc");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.vmware.com/");
 exit(0);
}

include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "VMware ESX detection (SNMP)";

port = get_kb_item("Services/snmp");
if(!port)port = 161;

if(!(get_udp_port_state(port)))exit(0);

sysdesc = get_kb_item("SNMP/sysdesc");
if(!sysdesc || "vmware" >!< tolower(sysdesc))exit(0);

version = eregmatch(pattern:"(VMware ESX ?(Server)?) ([0-9.]+)",string:sysdesc);

if(!isnull(version[1]) && !isnull(version[3])) {

  typ = version[1];
  vers = version[3];

  if(vers > 0) {
    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/o:vmware:esx:"); # even if it is an "ESXi", there is just "ESX" in sysdescr. 
    set_kb_item(name:"VMware/GSX-Server/snmp/version",value:vers);
  } else {
    cpe = "cpe:/o:vmware:esx";
    set_kb_item(name:"VMware/GSX-Server/snmp/version",value:"unknown");
    vers = "unknown";
  }  

  register_host_detail(name:"OS", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
  register_host_detail(name:"OS", value:"VMware ESX(i)", nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  set_kb_item(name:"VMware/ESX/installed",value:TRUE);

  if("build" >< sysdesc) {
    build = eregmatch(pattern:" build-([0-9]+)",string:sysdesc);
    if(!isnull(build[1])) {
      replace_kb_item(name:"VMware/ESX/build", value:build[1]);
    }   
  }  

  result_txt = 'Detected ' + typ  + ' Version: ';
  result_txt += vers;
  result_txt += '\nCPE: '+ cpe;
  result_txt += '\n\nConcluded from remote snmp sysDescr:\n';
  result_txt += sysdesc;
  result_txt += '\n';

  log_message(port:port, data:result_txt);

  exit(0);


}  


