# OpenVAS Vulnerability Test
# $Id: mldonkey_www.nasl 41 2013-11-04 19:00:12Z jan $
# Description: MLDonkey web interface detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Modified by Michael Meyer
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
tag_summary = "MLDonkey web interface might be running on this port. This peer to peer 
 software is used to share files.

 1. This may be illegal.
 2. You may have access to confidential files
 3. It may eat too much bandwidth";

tag_solution = "disable it";

# Note: this script is not very useful because mldonkey only allows
# connections from localhost by default

 desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

if(description)
{
  script_id(11125);
  script_version("$Revision: 41 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
 
  script_name("MLDonkey web interface detection");
  script_description(desc);
 
  summary = "Detect mldonkey web interface";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  family = "Peer-To-Peer File Sharing";
  script_family(family);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 4080);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.11125";
SCRIPT_DESC = "MLDonkey web interface detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
ports = add_port_in_list(list:get_kb_list("Services/www"), port:4080);

foreach port (ports)
{
 banner = get_http_banner(port: port);
 
 if( banner == NULL )continue;

 if( egrep(pattern: "MLDonkey", string: banner, icase:1) ) { 
  if( ! egrep(pattern:"failure", string: banner, icase:1 )) { 
     vers = string("unknown");
     if( ereg(pattern: "^HTTP/1\.[01] +403", string: banner) ) { 
       version = eregmatch(string: banner, pattern: "MLDonkey/([0-9]+\.*[0-9]*\.*[0-9]*)+");   
       if(!isnull(version[1]))vers=version[1]; 
     }     
     else if ( ereg(pattern: "^HTTP/1\.[01] +200", string: banner) ) { 
       req = http_get(item:string("/oneframe.html"), port:port);
       buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
       version = eregmatch(string: buf, pattern: "Welcome to MLDonkey ([0-9]+\.*[0-9]*\.*[0-9]*).*");
       if(!isnull(version[1]))vers=version[1];
       if(!islocalhost())ml_www_remote = TRUE;
     }  
  
   desc += string("\nMLDonkey Version (");
   desc += vers;
   desc += string(") was detected on the remote host.\n");
   if(ml_www_remote) {
     desc += string("\nRemote access to MLDonkey web interface from ");
     desc +=  this_host_name();
     desc +=  string(" is allowed!\n");
   }

   tmp_version = string(vers);
   set_kb_item(name: string("www/", port, "/MLDonkey/version"), value: tmp_version);

   ## build cpe and store it as host_detail
   register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+-?([a-z0-9]+)?)", tmpBase:"cpe:/a:mldonkey:mldonkey:");
   
   set_kb_item(name: string("MLDonkey/www/port/"), value: port);

   if(ml_www_remote) {
     set_kb_item(name: string("www/", port, "/MLDonkey/remote/"), value: 1);

     ## build cpe and store it as host_detail
     register_cpe(tmpVers:1, tmpExpr:"^([0-9.]+\.[0-9]).*([r0-9]+)?", tmpBase:"cpe:/a:mldonkey:mldonkey:");

   }

   security_note(port:port,data:desc);
   exit(0);
  } 
 }   
}
exit(0);
