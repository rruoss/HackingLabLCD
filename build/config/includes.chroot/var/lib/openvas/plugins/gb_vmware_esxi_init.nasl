###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_esxi_init.nasl 44 2013-11-04 19:58:48Z jan $
#
# VMware ESXi scan initialization.
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
tag_summary = "This NVT initiate an authenticated scan against ESXi and store some results in KB.";


if (description)
{
 
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 script_id(103447);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2012-03-14 14:54:53 +0100 (Wed, 14 Mar 2012)");
 script_name("VMware ESXi scan initialization");
 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 script_summary("Authenticate against ESXi and store information in kb");
 script_category(ACT_GATHER_INFO);
 script_family("VMware Local Security Checks");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_vmware_esx_web_detect.nasl");
 script_require_ports("Services/www", 443);
 script_require_keys("VMware/ESX/typ/ESXi","VMware/ESX/port");

 script_add_preference(name:"ESXi login name:", type:"entry", value:"");
 script_add_preference(name:"ESXi login pasword:", type:"password", value:"");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("vmware_esx.inc");

port = get_kb_item("VMware/ESX/port");

if(!port || !get_port_state(port)) {
  exit(0);
}  

user = script_get_preference("ESXi login name:");
pass = script_get_preference("ESXi login pasword:");

if(isnull(user) || isnull(pass)) {
  exit(0);
}  

esxi_version = get_kb_item("VMware/ESX/version");

if(!esxi_version) {
  log_message(data:string("It was NOT possible to retrieve the ESXi version. Local Security Checks for ESXi disabled.\n"));
  exit(0);
}

if(esxi_version !~ "^4\." && esxi_version !~ "^5\.") {
  log_message(data:string("Unsupported ESXi version. Currently ESXi 4.0, 4.1 and 5.0 and 5.1 are supported. We found ESXi version ", esxi_version, "\n"));
  exit(0);
}

if(esxi_version =~ "^4\.") {

  if(get_esxi4_x_vibs(port:port,user:user,pass:pass)) {

    set_kb_item(name:"VMware/ESXi/LSC", value:TRUE);
    log_message(data:string("It was possible to login and to get all relevant information. Local Security Checks for ESXi 4.x enabled.\n\nWe found the following bulletins installed on the remote ESXi:\n", installed_bulletins,"\n"), port:port);
    exit(0);

  } else {
    log_message(data:string("It was NOT possible to login and to get all relevant information. Local Security Checks for ESXi 4.x disabled.\n\nError: ", esxi_error,"\n"), port:port);
    exit(0);
  }

}

if(esxi_version =~ "^5\.") {

  if(get_esxi5_0_vibs(port:port,user:user,pass:pass)) {

    set_kb_item(name:"VMware/ESXi/LSC", value:TRUE);
    log_message(data:string("It was possible to login and to get all relevant information. Local Security Checks for ESXi 5.x enabled.\n\nWe found the following bulletins installed on the remote ESXi:\n", installed_bulletins,"\n"), port:port);
    exit(0);

  } else {
    log_message(data:string("It was NOT possible to login and to get all relevant information. Local Security Checks for ESXi 5.x disabled.\n\nError: ", esxi_error,"\n"), port:port);
    exit(0);
  }

}

exit(0);



