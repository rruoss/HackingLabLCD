###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sharepoint_39776.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft SharePoint Server 2007 '_layouts/help.aspx' Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "Microsoft SharePoint Server 2007 and SharePoint Services 3.0 are prone
to a cross-site scripting vulnerability because they fail to properly
sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.";

tag_solution = "The vendor has released an advisory and updates. Please see the
references for details.";

if (description)
{
 script_id(103254);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)");
 script_bugtraq_id(39776);
 script_cve_id("CVE-2010-0817");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("Microsoft SharePoint Server 2007 '_layouts/help.aspx' Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39776");
 script_xref(name : "URL" , value : "http://blogs.technet.com/msrc/archive/2010/04/29/security-advisory-983438-released.aspx");
 script_xref(name : "URL" , value : "http://office.microsoft.com/en-us/sharepointserver/FX100492001033.aspx");
 script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_in_microsoft_sharepoint_server_2007.html");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/511021");
 script_xref(name : "URL" , value : "http://support.avaya.com/css/P8/documents/100089744");
 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/983438.mspx");
 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS10-039.mspx");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Microsoft SharePoint is prone to a cross-site scripting vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0); 
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_asp(port:port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "sharepoint" >!< tolower(banner))exit(0);

url = string(dir,"/_layouts/help.aspx?cid0=MS.WSS.manifest.xml%00%3Cscript%3Ealert%28%27OpenVAS-XSS-Test%27%29%3C/script%3E&tid=X"); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('OpenVAS-XSS-Test'\)</script><br/>",check_header:TRUE)) {
     
  security_warning(port:port);
  exit(0);

}


exit(0);

