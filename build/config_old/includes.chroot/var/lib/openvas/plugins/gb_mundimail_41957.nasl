###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mundimail_41957.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mundi Mail Multiple Remote Command Execution Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "Mundi Mail is prone to multiple remote command-execution
vulnerabilities because it fails to properly validate user-
supplied input.

An attacker can exploit these issues to execute arbitrary commands
within the context of the vulnerable system.

MundiMail version 0.8.2 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(100727);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)");
 script_bugtraq_id(41957);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Mundi Mail Multiple Remote Command Execution Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41957");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/mundimail/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if Mundi Mail is prone to a remote command-execution vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
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
if(!can_host_php(port:port))exit(0);

dirs = make_list("/mundimail","/mail",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/admin/index.php"); 

  if(http_vuln_check(port:port, url:url,pattern:"Powered by Mundi Mail")) {
    
    url = string(dir,"/admin/status/index.php?action=stop&mypid=;id");

    if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
      security_hole(port:port);
      exit(0);
    }
  }
}

exit(0);
