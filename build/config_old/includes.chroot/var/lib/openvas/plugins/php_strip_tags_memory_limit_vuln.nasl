# OpenVAS Vulnerability Test
# $Id: php_strip_tags_memory_limit_vuln.nasl 17 2013-10-27 14:01:43Z jan $
# Description: php < 4.3.8
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
tag_summary = "The remote host is running a version of PHP 4.3 which is older or equal to 
4.3.7.

PHP is a scripting language which acts as a module for Apache or as a standalone
interpreter. There is a bug in the remote version of this software which may
allow an attacker to execute arbitrary code on the remote host if the option
memory_limit is set. Another bug in the function strip_tags() may allow
an attacker to bypass content-restrictions when submitting data and may
lead to cross-site-scripting issues.";

tag_solution = "Upgrade to PHP 4.3.8";

# ref: Stefan Esser 

if(description)
{
 script_id(13650);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10724, 10725);
 script_cve_id("CVE-2004-0594","CVE-2004-0595");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "php < 4.3.8";
 script_xref(name:"OSVDB", value:"7870");
 script_xref(name:"OSVDB", value:"7871");

 script_name(name);
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Checks for version of PHP";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
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
include("backport.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner)exit(0);
php = get_php_version(banner:banner);
if (! php ) exit(0);

if(ereg(pattern:"PHP/4\.3\.[0-7][^0-9]", string:php))
   security_hole(port);
