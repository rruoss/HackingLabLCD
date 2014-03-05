###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_cms_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Moodle CMS Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Modified 2009-03-25 Michael Meyer
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
tag_summary = "This host is running moodle.
  Moodle is a Course Management System (CMS), also known as a Learning
  Management System (LMS) or a Virtual Learning Environment (VLE). It
  is a Free web application that educators can use to create effective
  online learning sites.";

# need desc here to modify it later in script.
desc = "

  Summary:
  " + tag_summary;


if(description)
{
  script_id(800239);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Moodle CMS Version Detection");

  script_description(desc);
  script_summary("Set Version of Moodle CMS in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://moodle.org/");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800239";
SCRIPT_DESC = "Moodle CMS Version Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dirs = make_list("/moodle",cgi_dirs());

foreach dir (dirs) {

 url = string(dir, "/index.php"); 
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
 if( buf == NULL )continue;

 if(
    egrep(pattern: "^Set-Cookie: MoodleSession", string: buf) ||
    egrep(pattern: '<a [^>]*href="http://moodle\\.org/"[^>]*><img [^>]*src="pix/moodlelogo.gif"', string: buf)
   )
    { 
       if(strlen(dir)>0) {
         install=dir;
       } else {
         install=string("/");
       }

       version = string("unknown");
       ver = eregmatch(string: buf, pattern: "title=.Moodle ([0-9.]+)\+*.*[(Build: 0-9)]*");
	
       if(!isnull(ver[1])) {
        version = ver[1];
       } else {
        # not really accurate, but better then nothing
	url = string(dir, "/mod/hotpot/README.TXT");
	req = http_get(item:url, port:port);
	buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 
	if(!isnull(buf)) { 
	 ver = eregmatch(string: buf, pattern: "HotPot module for Moodle ([0-9.]+)"); 
	 if(!isnull(ver[1])) {
	  version = ver[1];
	  not_accurate = TRUE;
	 }  
	}  
       }

       tmp_version = string(version, " under ", install);
       set_kb_item(name:string("www/", port, "/moodle"), value:tmp_version);

       ## build cpe and store it as host_detail
       register_cpe(tmpVers: tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:moodle:moodle:");

       set_kb_item(name:"Moodle/Version", value:version);

       ## build cpe and store it as host_detail
       register_cpe(tmpVers: version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:moodle:moodle:");

       desc += string("\nmoodle Version '");
       desc += string(version);
       desc += string("' was detected on the remote host in the following directory:\n\n");
       desc += string(install, "\n"); 

       if(not_accurate) {
	desc += string("\nOpenVAs was not able to extract the exact version number. Further tests on moodle\ncould lead in false positives.\n\n");
       }	 

       security_note(port:port,data:desc);
       exit(0);
  }	
}
