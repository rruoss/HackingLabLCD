###############################################################################
# OpenVAS Vulnerability Test
# $Id: jd_web_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# JDownloader Web Detection
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
tag_summary = "JDownloader ##WEBSERVICE## is running at this port. JDownloader is open
source, platform independent and written completely in Java. It
simplifies downloading files from One-Click-Hosters like
Rapidshare.com or Megaupload.com.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 script_id(100301);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-11 19:51:15 +0200 (Sun, 11 Oct 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("JDownloader Web Detection");
 script_description(desc);
 script_summary("Checks for the presence of JDownloader Webinterface and/or Webserver");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8765, 9666);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://jdownloader.org");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100301";
SCRIPT_DESC = "JDownloader Web Detection";

port = get_http_port(default:8765);
if(!get_port_state(port))exit(0);

 url = string("/");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )exit(0);

 if('WWW-Authenticate: Basic realm="JDownloader' >< buf) {
  
  JD = TRUE;
  JD_WEBINTERFACE = TRUE;
  set_kb_item(name:string("www/", port, "/password_protected"), value:TRUE);

  userpass  = string("JD:JD"); # default pw
  userpass64 = base64(str:userpass);
  req = string("GET / HTTP/1.0\r\nAuthorization: Basic ",userpass64,"\r\n\r\n");
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  
  if(buf) {  
    if("JDownloader - WebInterface" >< buf) {
      DEFAULT_PW = TRUE;
      set_kb_item(name:string("www/", port, "/jdwebinterface/default_pw"), value:TRUE);
      version = eregmatch(pattern:"Webinterface-([0-9]+)", string:buf);
    }  
  }  
 } 
 else if("JDownloader - WebInterface" >< buf) {
  JD = TRUE;
  JD_WEBINTERFACE = TRUE;
  JD_UNPROTECTED = TRUE;
  version = eregmatch(pattern:"Webinterface-([0-9]+)", string:buf);
 } 
 else if("Server: jDownloader" >< buf) {
   JD = TRUE;
   JD_WEBSERVER = TRUE;
   set_kb_item(name:string("www/", port, "/jdwebserver"), value:TRUE);
 }  
   

 if(JD) {

   if(JD_WEBINTERFACE) {

      if(version && !isnull(version[1])) {
       vers = version[1];
      } else {
       vers = string("unknown");
      }   

      set_kb_item(name: string("www/", port, "/jdwebinterface"), value: string(vers));
  
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:string(vers), exp:"^([0-9.]+)", base:"");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      info  = string("\n\nJDownloader Webinterface Version '");
      info += string(vers);
      info += string("' was detected on the remote host\n");

      desc  = ereg_replace(
                string:desc,
		pattern:"##WEBSERVICE##",
		replace:"Webinterface"
		);
      
      if(JD_UNPROTECTED) {
         info += string("\nJDownloader Webinterface is *not* protected by password.\n");
      } 
      else if(DEFAULT_PW) {
         info += string("\nIt was possible for OpenVAS to log in into the JDownloader Webinterface\nby using 'JD' (the default username and password) as username and password.\n");
      }  

      desc = desc + info;

   }

   if(JD_WEBSERVER) {
     desc = ereg_replace(
               string:desc,
               pattern:"##WEBSERVICE##",
               replace:"HTTP Server"
               );
   }  

       if(report_verbosity > 0) {
         security_note(port:port,data:desc);
       }
       exit(0);

 }

exit(0);

