###############################################################################
# OpenVAS Vulnerability Test
# $Id: mambo_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# mambo Detection
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
tag_summary = "This host is running mambo a widely installed Open Source cms solution.";

# need desc here to modify it later in script.
desc = "

 Summary:
 " + tag_summary;


if (description)
{
 script_id(100036);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("mambo Detection");  

 script_description(desc);
 script_summary("Checks for the presence of mambo");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.mamboserver.com");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100036";
SCRIPT_DESC = "mambo Detection";

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dirs = make_list("/mambo","/cms",cgi_dirs());

foreach dir (dirs) {

 url = string(dir, "/index.php"); 
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
 if( buf == NULL )continue;

 if( 
    egrep(pattern: "^Set-Cookie: mosvisitor=1", string: buf)   ||
    egrep(pattern: '.*meta name="description" content="This site uses Mambo.*', string: buf) ||
    egrep(pattern: '.*meta name="Generator" content="Mambo.*', string: buf) ||
    egrep(pattern: '.*http://mambo-foundation.org<[^>]+>Mambo.*', string: buf)
   )
 { 
	  if(strlen(dir)>0) {
	        install=dir;
	  } else {
	        install=string("/");
	  }

 } else {

  	url = string(dir, "/htaccess.txt");
        req = http_get(item:url, port:port);
        buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
	if( buf == NULL )continue;

	if(
		egrep(pattern: ".*# @package Mambo.*", string: buf)
	  )
	{
		if(strlen(dir)>0) {
	             install=dir;
          	} else {
        	     install=string("/");
          	}		

	} else {

		url = string(dir, "/README.php");
		req = http_get(item:url, port:port);
		buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
		if( buf == NULL )continue;

		if(
		   egrep(pattern: "^Mambo is Open Source software.*", string: buf)	
		  )
		{
			if(strlen(dir)>0) {     
        	             install=dir;
	                } else {
                	     install=string("/");
                	}
	
		} else {

			url = string(dir, "/includes/js/mambojavascript.js");
			req = http_get(item:url, port:port);
			buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
			if( buf == NULL )continue;

			if(
			   egrep(pattern: ".*@package Mambo.*", string: buf)
			  )
			{
				if(strlen(dir)>0) {
				   install=dir;
				} else {
				   install=string("/");	
				}

			}

		}
	}

 }

 if(install) {

 vers = string("unknown");
 #try to get version
  
	 url = string(dir, "/administrator/components/com_admin/version.xml");
	 req = http_get(item:url, port:port);
	 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
	 version = eregmatch(string: buf, pattern: "<version>(.*)</version>");

	 if ( !isnull(version[1]) ) {
		vers=version[1];
         } else {

	   url = string(dir, "/mambots/content/moscode.xml");
           req = http_get(item:url, port:port);
           buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 	   version = eregmatch(string: buf, pattern: ".*<version>(.*)</version>.*");

	   if ( !isnull(version[1]) ) {
		vers=version[1];
	   } else {

	     url = string(dir, "/help/mambo.whatsnew.html");
             req = http_get(item:url, port:port);
	     buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
	     version = eregmatch(string: buf, pattern: ".*<h1>.*New in Version (.*)</h1>.*");

	     if ( !isnull(version[1]) ) {
		vers=version[1];
	     }			
	  }

	}	

        tmp_version = string(vers," under ",install);
 	set_kb_item(name: string("www/", port, "/mambo_mos"), value: tmp_version);

        ## build cpe and store it as host_detail
        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:mambo-foundation:mambo:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

        info = string("\n\nmambo Version (");
        info += string(vers);
        info += string(") was detected on the remote host in the following directory(s):\n\n");
	info += string(install, "\n"); 

	desc = desc + info; 

	if(report_verbosity > 0) {
	  security_note(port:port,data:desc);
	}  
        exit(0);
 }	
}
exit(0);
