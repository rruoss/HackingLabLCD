###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phplist_49188.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHPList Security Bypass and Information Disclosure Vulnerabilities
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
tag_summary = "PHPList is prone to a security-bypass vulnerability and an information-
disclosure vulnerability.

An attacker can exploit these issues to gain access to sensitive
information and send arbitrary messages to registered users. Other
attacks are also possible.";


if (description)
{
 script_id(103231);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-08-29 15:19:27 +0200 (Mon, 29 Aug 2011)");
 script_bugtraq_id(49188);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_name("PHPList Security Bypass and Information Disclosure Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49188");
 script_xref(name : "URL" , value : "http://www.phplist.com");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519295");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed PHPList is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_phplist_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"phpList"))exit(0);

for(i=1; i<50; i++) {

  url = string(dir, "/lists/?p=forward&uid=foo&mid=",i); 

  if(http_vuln_check(port:port, url:url,pattern:"Forwarding the message with subject")) {
     
    security_warning(port:port);
    exit(0);

  }
}
exit(0);
