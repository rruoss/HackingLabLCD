# OpenVAS Vulnerability Test
# $Id: moodle_php_reply_variable_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Moodle post.php XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "The version of Moodle on the remote host contains a flaw that allows a
remote cross site scripting attack because the application does not
validate the 'reply' variable upon submission to the 'post.php'
script. 

This could allow a user to create a specially crafted URL that would execute
arbitrary code in a user's browser within the trust relationship between the 
browser and the server, leading to a loss of integrity.";

tag_solution = "Upgrade to Moodle 1.4 or newer.";

#  Ref: Javier Ubilla and Ariel

if (description)
{
 script_id(14257);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1711");
 script_bugtraq_id(10884);
 script_xref(name:"OSVDB", value:"8383");
 
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Moodle post.php XSS");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 script_summary("Determines if Moodle is vulnerable to post.php XSS");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_dependencies("gb_moodle_cms_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Moodle/Version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))
	exit(0);
if(!can_host_php(port:port))
	exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  req = http_get(item:string(dir, "/post.php?reply=<script>document.write('OpenVAS plugin to detect post.php flaw');</script>"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if(res == NULL ) 
    exit(0);
 
  if (ereg(pattern:"OpenVAS plugin to detect post.php flaw", string:res ))
  {
    security_warning(port);
    exit(0);
  }
}
