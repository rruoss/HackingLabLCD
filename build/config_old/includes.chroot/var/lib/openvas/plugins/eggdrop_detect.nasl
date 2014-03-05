###############################################################################
# OpenVAS Vulnerability Test
# $Id: eggdrop_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Eggdrop Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "This Host is running Eggdrop, an Open Source IRC bot.";

# need desc here to modify it later in script.
desc = "

 Summary:
 " + tag_summary;


if (description)
{
 script_id(100206);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-16 14:32:16 +0200 (Sat, 16 May 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("Eggdrop Detection");  

 script_description(desc);
 script_summary("Checks for the presence of Eggdrop");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/eggdrop",3333 );
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.eggheads.org/");
 exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("global_settings.inc");
include("telnet_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100206";
SCRIPT_DESC = "Eggdrop Detection";

port = get_kb_item("Services/eggdrop");

if(!port) {
 port = 3333;
}  

if(!get_port_state(port))exit(0);

banner = get_telnet_banner(port:port);

if(isnull(banner)) {
   exit(0);
}   

 if(egrep(pattern:"Eggdrop", string: banner, icase:TRUE)) {

      version = eregmatch(string: banner, pattern: "\(Eggdrop v([0-9.]+[^ ]*) \(",icase:TRUE);

      if ( !isnull(version[1]) ) {
         vers=version[1];
      } 

      set_kb_item(name: string("eggdrop/version/", port), value: vers);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value: vers, exp:"^([0-9.]+)",base:"cpe:/a:eggheads:eggdrop:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      info = string("\n\nEggdrop Version '");
      info += string(vers);
      info += string("' was detected on the remote host\n");

      desc = desc + info;    
       
         if(report_verbosity > 0) {
           security_note(port:port,data:string(desc));
           exit(0);
         }	 

}	 
exit(0);
