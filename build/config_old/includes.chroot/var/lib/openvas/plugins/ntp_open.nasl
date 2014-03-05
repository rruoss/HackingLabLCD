# OpenVAS Vulnerability Test
# $Id: ntp_open.nasl 41 2013-11-04 19:00:12Z jan $
# Description: NTP read variables
#
# Authors:
# David Lodge
# Changes by rd:
# - recv() only receives the first two bytes of data (instead of 1024)
# - replaced ord(result[0]) == 0x1E by ord(result[0]) & 0x1E (binary AND)
#
# Copyright:
# Copyright (C) 2002 David Lodge
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
tag_summary = "A NTP (Network Time Protocol) server is listening on this port.";

if(description)
{
  script_id(10884);
  script_version("$Revision: 41 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  name = "NTP read variables";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);

  summary = "NTP allows query of variables";
  script_summary(summary);
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 David Lodge");
  family = "Service detection";
  script_family(family);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("host_details.inc");
include("cpe.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.10884";
SCRIPT_DESC = "NTP read variables";

function ntp_read_list()
{
    data = raw_string(0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00);
    soc = open_sock_udp(123);
    send(socket:soc, data:data);
    r = recv(socket:soc, length:4096);
    close(soc);

    if (! r) return(NULL);

    p = strstr(r, "version=");
    if (! p) p = strstr(r, "processor=");
    if (! p) p = strstr(r, "system=");
    p = ereg_replace(string:p, pattern:raw_string(0x22), replace:"'");

    if (p) return(p);
    return(NULL);
}


function ntp_installed()
{
  data = raw_string(0xDB, 0x00, 0x04, 0xFA, 0x00, 0x01,
    		    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0xBE, 0x78, 0x2F, 0x1D, 0x19, 0xBA,
		    0x00, 0x00);

  soc = open_sock_udp(123);
  send(socket:soc, data:data);
  r = recv(socket:soc, length:4096);
  close(soc);

  if(strlen(r) > 10)
  {
    return(r);
  }
  return(NULL);
}


# find out whether we can open the port

if( !(get_udp_port_state(123)) ) exit(0);

r = ntp_installed();

if(r)
{
  set_kb_item(name:"NTP/Running", value:TRUE);
  list = ntp_read_list();
  if(!list)
    security_note(port:123, protocol:"udp");
   else
   {

     if ("system" >< list )
     {
        s = egrep(pattern:"system=", string:list);
	os = ereg_replace(string:s, pattern:".*system='([^']*)'.*", replace:"\1");
        set_kb_item(name:"Host/OS/ntp", value:os);
        register_host_detail(name:"OS", value:os, nvt:"1.3.6.1.4.1.25623.1.0.10884",
          desc:"NTP allows query of variables");
     }

     if ("processor" >< list )
     {
        s = egrep(pattern:"processor=", string:list);
	os = ereg_replace(string:s, pattern:".*processor='([^']*)'.*", replace:"\1");
        set_kb_item(name:"Host/processor/ntp", value:os);
     }

     if("ntpd" >< list)
     {
       ntpVerFull = eregmatch(pattern:"version='([^']+)',", string:list);
       if( ! isnull(ntpVerFull[1])) {
         set_kb_item(name:"NTP/Linux/FullVer", value:ntpVerFull[1]);
       }	 

       ntpVer = eregmatch(pattern:"ntpd ([0-9.]+)([a-z][0-9]+)?-?(RC[0-9]+)?", string:list);
       if(ntpVer[1] != NULL)
       {

         if(ntpVer[2] =~ "[a-z][0-9]+" && ntpVer[3] =~ "RC"){
              ntpVer = ntpVer[1] + "." + ntpVer[2] + "." + ntpVer[3];
         }
         else if(ntpVer[2] =~ "[a-z][0-9]+"){
              ntpVer = ntpVer[1] + "." + ntpVer[2];
         }
         else ntpVer = ntpVer[1];

         set_kb_item(name:"NTP/Linux/Ver", value:ntpVer);
   
         ## build cpe and store it as host_detail
         cpe = build_cpe(value:ntpVer, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:ntp:ntp:");
         if(!isnull(cpe))
            register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

       }
     }

     report = "It is possible to determine a lot of information about the remote host
     by querying the NTP (Network Time Protocol) variables - these include
     OS descriptor, and time settings.
     It was possible to gather the following information from the remote NTP host :
     " + list + "

     Quickfix: Set NTP to restrict default access to ignore all info packets:
     restrict default ignore";
     security_note(port:123, protocol:"udp", data:report);
   }
}
