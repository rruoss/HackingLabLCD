# OpenVAS Vulnerability Test
# $Id: vbulletin_detect.nasl 41 2013-11-04 19:00:12Z jan $
# Description: vBulletin Detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "This script detects whether vBulletin discussion forum is running 
on the remote host, and extracts its version if it is.";

if(description)
{
 script_id(17282);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "vBulletin Detection";
 script_name(name);
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Checks for the presence of vBulletin";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.17282";
SCRIPT_DESC = "vBulletin Detection";

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


foreach d (make_list("/forum", cgi_dirs()))
{
 req = http_get(item:string(d, "/index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 res = egrep(pattern:" content=.vBulletin ", string:res, icase:TRUE);
 if( res )
 {

  if(strlen(dir)>0) {
    install=dir;
  } else {
    install=string("/");
  }    
			           
  vers = ereg_replace(pattern:".*vBulletin ([0-9.]+).*", string:res, replace:"\1", icase:TRUE);

  tmp_version = string(vers," under ",install);
  set_kb_item(name:string("www/", port, "/vBulletin"), value:tmp_version);
  set_kb_item(name:"vBulletin/installed",value:TRUE);
   
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:vbulletin:vbulletin:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  rep = "The remote host is running vBulletin " + vers + " under " + install;
  security_note(port:port, data:rep);
  exit(0);     
 }
} 
