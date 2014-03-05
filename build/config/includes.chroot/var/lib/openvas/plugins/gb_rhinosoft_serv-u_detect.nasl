###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rhinosoft_serv-u_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Rhino Software Serv-U Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script detects the installed version of Rhino Software
  Serv-U and sets the result in KB.";

if(description)
{
  script_id(801117);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Rhino Software Serv-U Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Rhino Software Serv-U");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "ssh_detect.nasl");
  script_require_ports("Services/ftp", 21, "Services/ssh", 22);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ftp_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801117";
SCRIPT_DESC = "Rhino Software Serv-U Version Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
function ServuGetVer(su_port, pat)
{
  if(get_port_state(su_port))
  {
    banner = get_ftp_banner(port:su_port);
    if("Serv-U" >< banner)
    {
      ver = eregmatch(pattern:pat, string:banner);
      return ver;
    }
    else
      return NULL;
  }
}


servuPort = get_kb_item("Services/ssh");

if(!servuPort){
  servuPort = 22;
}

pattern1 = "Serv-U_([0-9.]+)";
pattern2 = "Serv-U FTP Server v([0-9.]+)";

servuVer = ServuGetVer(su_port:servuPort, pat:pattern1);
if(!isnull(servuVer[1])){
  set_kb_item(name:"Serv-U/FTP/Ver", value:servuVer[1]);

  ## build cpe and store it as host_detail
  register_cpe(tmpVers:servuVer[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:rhinosoft:serv-u:");
}
else
{
  servuPort = get_kb_item("Services/ftp");
  if(!servuPort){
    servuPort = 21;
  }

  if(get_port_state(servuPort)) {

    soc = open_sock_tcp(servuPort);

    if (soc) {
    
      banner = ftp_recv_line(socket:soc);
    
      if("220 Serv-U" >< banner) {

         req = string("CSID\r\n");
         send(socket:soc, data:req);
         buf = ftp_recv_line(socket:soc);
    
         if(!isnull(buf)) {
            if("200 Name=Serv-U" >< buf) {
               version = eregmatch(string: buf, pattern:"Version=([^;]+);");
            }
         }
    
      }

      ftp_close(socket:soc);
    }
  }

  if(!isnull(version[1])) {
  
    set_kb_item(name:"Serv-U/FTP/Ver", value:version[1]);

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:version[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:rhinosoft:serv-u:");

    set_kb_item(name:string("ftp/", servuPort, "/Serv-U"), value:version[1]);
    security_note(data:"Rhino Software Serv-U FTP version " + version[1] + 
                           " was detected on the host");

    ## build cpe and store it as host_detail
    register_cpe(tmpVers:version[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:rhinosoft:serv-u:");


  } else {

      servuVer = ServuGetVer(su_port:servuPort, pat:pattern2);
      if(!isnull(servuVer[1]))
      { # This check is inaccurate for 9.x versions (Don't know about versions <9)
        # but better then nothing. Version 9 Banner is "220 Serv-U FTP Server v9.0
        # ready..." while real version is 9.0.0.5. 
        set_kb_item(name:"Serv-U/FTP/Ver", value:servuVer[1]);
        security_note(data:"Rhino Software Serv-U FTP version " + servuVer[1] + 
                           " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:servuVer[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:rhinosoft:serv-u:");

      }
    }
}
