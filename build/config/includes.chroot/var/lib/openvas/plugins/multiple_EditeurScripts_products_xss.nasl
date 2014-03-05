###############################################################################
# OpenVAS Vulnerability Test
# $Id: multiple_EditeurScripts_products_xss.nasl 15 2013-10-27 12:49:54Z jan $
#
# Multiple EditeurScripts Products 'msg' Parameter Cross Site
# Scripting Vulnerability
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
tag_summary = "Multiple EditeurScripts products are prone to a cross-site scripting
  vulnerability because they fail to sufficiently sanitize
  user-supplied data.

  An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based
  authentication credentials and to launch other attacks.

  The following products and versions are affected.

  -EScontacts v1.0
  -EsBaseAdmin  v2.1
  -EsPartenaires v1.0   
  -EsNews v1.2

  Other versions may also be affected. 

 See Also:
  http://www.securityfocus.com/bid/34112/discuss";


# need desc here to modify it later in script.

desc = "

 Summary:
 " + tag_summary;

if (description)
{
 script_id(100049);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-16 12:53:50 +0100 (Mon, 16 Mar 2009)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2008-6868");
 script_bugtraq_id(34112);
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Multiple EditeurScripts Products 'msg' Parameter Cross Site Scripting Vulnerability");
 script_description(desc);
 script_summary("Determine if EditeurScripts Products 'msg' Parameter is prone to Cross Site Scripting vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
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

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dir = make_list("/EsContacts","/EsBaseAdmin/default","/EsPartenaires","/EsNews/admin/news");
x = 0;

foreach d (dir)
{ 
 
 site = "/login.php"; 

 if(d == "/EsNews/admin/news") {
  site = "/modifier.php";
 }  

 url = string(d, site, '?msg=<script>alert(document.cookie);</script>');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( buf == NULL )continue;

 if ( egrep(pattern:"<script>alert\(document\.cookie\);</script>", string: buf)  )
 	{    
	  es_soft = eregmatch(string:d, pattern:"/([a-zA-Z]+)/*.*");
          if(!isnull(es_soft[1])) {
	    vuln_essoft_found[x] = es_soft[1];
          }
        }
 x++; 
}

if(vuln_essoft_found) {
  info = string("\n\nThe following vulnerable EditeurScripts products were detected on the remote host:\n\n");
  foreach found (vuln_essoft_found) {
   if(!isnull(found)) { 
    vuln=TRUE;
    info += string("  ",found,"\n");
   }
  }  

 desc = desc + info;

 if(vuln) {
  security_warning(port:port,data:desc); 
  exit(0);
 }
}  

exit(0);
