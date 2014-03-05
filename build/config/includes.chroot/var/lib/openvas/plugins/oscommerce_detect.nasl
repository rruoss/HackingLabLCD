###############################################################################
# OpenVAS Vulnerability Test
# $Id: oscommerce_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# osCommerce Detection
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
tag_summary = "This host is running osCommerce, a widely installed open source shopping e-commerce solution.
See http://www.oscommerce.com for more information.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;

if (description)
{
 script_id(100001);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-02-26 04:52:45 +0100 (Thu, 26 Feb 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("osCommerce Detection");  

 script_description(desc);
 script_summary("Checks for the presence of OsCommerce");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dirs = make_list("/osc","/oscommerce","/store","/catalog","/shop",cgi_dirs());
x=0;

foreach dir (dirs) {

 url = string(dir, "/index.php"); 
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
 if( buf == NULL ) exit(0);;

 ### looking for osCsid. If found, it is a osc
 if( "osCsid" >< buf || buf =~ "Powered by.*osCommerce")  
  { 
    if(strlen(dir)>0) {   
        installations[x] = dir;
    } else {
    	installations[x] = string("/");
    }	
  }
   ### If osCsid not found, look for typical osc files.
  else if  ( egrep(pattern:".*Location:.*login.php\?+.*=+.*", string: buf) ||             
            (egrep(pattern: "Set-Cookie:.*cookie_test=please_accept_for_session", string: buf1) && 
    	     egrep(pattern: "Location:.*login.php.*", string: buf1)) )  
  {     
    url1 = string(dir, "/address_book_process.php"); 
    req1 = http_get(item:url1, port:port);
    buf1 = http_keepalive_send_recv(port:port, data:req1, bodyonly:FALSE); 
    if( buf1 == NULL ) exit(0);     

    if ( egrep(pattern:".*Location:.*login.php\?+.*=+.*", string: buf) ||             
        (egrep(pattern: "Set-Cookie:.*cookie_test=please_accept_for_session", string: buf1) && 
    	 egrep(pattern: "Location:.*login.php.*", string: buf1)) )  
    {             
       url2 = string(dir, "/product_info.php"); 
       req2 = http_get(item:url2, port:port);
       buf2 = http_keepalive_send_recv(port:port, data:req2, bodyonly:FALSE); 
       if( buf2 == NULL ) exit(0); 

       if (ereg(pattern: "^HTTP/1\.[01] +200", string: buf2)) {       
           if(strlen(dir)>0) {   
    	        installations[x] = dir;
    	   } else {
        	installations[x] = string("/");
    	   }	
       }
    } 
  }  
  x++;
}

if(installations) {
    info = string("\n\nOsCommerce was detected on the remote host in the following directory(s):\n\n"); 
    foreach found (installations) {
    	if (!get_kb_item("Software/osCommerce")) {
    	    set_kb_item(name:"Software/osCommerce", value: TRUE);
	}     
    	info += string(found, "\n"); 
    	set_kb_item(name:"Software/osCommerce/dir", value: found);
	set_kb_item(name: string("www/", port, "/oscommerce"), value: string("unknown under ",found));
    }
   
    desc = desc + info;    
   
   if(report_verbosity > 0) { 
     security_note(port:port,data:desc);
   }  
   exit(0);
}

exit(0);
