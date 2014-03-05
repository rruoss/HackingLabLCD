##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpmyadmin_detect_900129.nasl 42 2013-11-04 19:41:32Z jan $
# Description: phpMyAdmin Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_summary = "Detection of phpMyAdmin.
                    
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900129";

if(description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2008-10-03 15:12:54 +0200 (Fri, 03 Oct 2008)");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_name("phpMyAdmin Detection");
 script_summary("Set File Version of phpMyAdmin in KB and report about it");

 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


 include("http_func.inc");
 include("http_keepalive.inc");
 include("cpe.inc");
 include("host_details.inc");

 ## Constant values
 port = get_http_port(default:80);
 if(!port){
        exit(0);
 }

 x = 0;
 foreach dir (make_list("/phpmyadmin","/phpMyAdmin","/pma", cgi_dirs()))
 {
        sndReq = http_get(item:string(dir, "/index.php"), port:port);
        rcvRes = http_keepalive_send_recv(port:port, data:sndReq);
        if(rcvRes == NULL){
          exit(0);
        }

        if(
            egrep(pattern:"^Set-Cookie: pma_.*", string:rcvRes)       ||
	    egrep(pattern:"^Set-Cookie: phpMyAdmin.*",string:rcvRes)  ||
	    egrep(pattern:"phpMyAdmin was unable to read your configuration file",string:rcvRes)  ||
	    egrep(pattern:"<title>phpMyAdmin.*", string:rcvRes)       ||
            egrep(pattern:"href=.*phpmyadmin.css.php")                ||
	   (egrep(pattern:"pma_password", string:rcvRes) && egrep(pattern:"pma_username", string:rcvRes)) 	
          )
        {
                phpmaVer = eregmatch(pattern:"phpMyAdmin (([0-9.]+)(-[rc0-9]*)?)", string:rcvRes);

		if(isnull(phpmaVer[0])) {
		  version = string("unknown");
		} else {
		  version = phpmaVer[1];
		}                
 
	 	  if(dir == "")dir = string("/");

	  pw_protected=0;

	  if(egrep(pattern:"1045", string:rcvRes) || 
	     egrep(pattern:"phpMyAdmin was unable to read your configuration file", string:rcvRes)) { 
	     pw_protected=2; # broken config
	  }
	  
	  if(egrep(pattern:"pma_username", string:rcvRes) &&
	     egrep(pattern:"pma_password", string:rcvRes)) { 
	     pw_protected=1; # username password required
	  } 
	  
          tmp_version = version + " under " + dir;
          set_kb_item(name:"www/"+ port + "/phpMyAdmin", value:tmp_version);
               
	  installations[x] = string(tmp_version + ":" + pw_protected + "");
	  x++;
                 
      }
 }
 

if(installations) {

  set_kb_item(name:"phpMyAdmin/installed",value:TRUE);

 foreach found (installations) {

  infos = eregmatch(pattern:"(.*) under (/.*):+([0-2]+)", string:found);
  ver = infos[1];
  dir = infos[2];
  protected = infos[3];

  cpe = build_cpe(value:ver, exp:"^([0-9.]+).*([rc0-9]*)?", base:"cpe:/a:phpmyadmin:phpmyadmin:");
  if(!cpe)
    cpe = 'cpe:/a:phpmyadmin:phpmyadmin';

  if(protected == 0) {
   info = '\n(Not protected by Username/Password)\n';
  }
  else if(protected == 2) {
    info = '\n(Problem with configuration file)\n';
  }

  register_product(cpe:cpe, location:dir, nvt:SCRIPT_OID, port:port);

  log_message(data: build_detection_report(app:"phpMyAdmin", version:ver, install:dir, cpe:cpe, concluded: ver, extra: info),
              port:port);

 }

}

exit(0);
