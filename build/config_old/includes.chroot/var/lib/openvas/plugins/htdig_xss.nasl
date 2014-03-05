# OpenVAS Vulnerability Test
# $Id: htdig_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ht://Dig htsearch.cgi XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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
tag_solution = "Upgrade to a newer when available";

tag_summary = "The 'htsearch' CGI, which is part of the ht://Dig package, 
is vulnerable to cross-site scripting attacks,
throught 'words' variable.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity.";

# Ref: Howard Yeend <h_bugtraq@yahoo.com>

if(description)
{
 script_id(15706);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2002-2010");
 script_bugtraq_id(5091);
 script_xref(name:"OSVDB", value:"7590");
 
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "ht://Dig htsearch.cgi XSS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks if ht://Dig is vulnerable to XSS flaw in htsearch.cgi";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Web application abuses";
 script_family(family);
  script_dependencies("cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
   foreach dir (cgi_dirs())
   {
  	buf = http_get(item:string(dir,"/htsearch.cgi?words=%22%3E%3Cscript%3Efoo%3C%2Fscript%3E"), port:port);
  	r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  	if( r == NULL )exit(0);
  	if(egrep(pattern:"<script>foo</script>", string:r))
  	{
    		security_warning(port);
	 	exit(0);
  	}
   }
}
