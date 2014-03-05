# OpenVAS Vulnerability Test
# $Id: phpshop_sql_injection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Multiple phpShop Vulnerabilities
#
# Authors:
# Noam Rathaus
# changes by rd:
# - language-insensitive egrep() matching
# - description
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
tag_summary = "The remote web server contains several PHP scripts that suffer from
multiple vulnerabilities. 

Description :

The remote host is running phpShop, a PHP-based e-commerce application
and PHP development framework. 

Multiple vulnerabilities have been discovered in this product, which may
allow a remote attacker to send arbitrary SQL commands to the remote
database, or to insert malicious HTML and/or JavaScript into existing
pages.";

tag_solution = "Upgrade to the latest version of phpShop.";

# From: JeiAr [security@gulftech.org]
# Subject: phpShop Vulnerabilities
# Date: Friday 16/01/2004 03:14

if(description)
{
  script_id(12022);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9437);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:R/AC:L/Au:N/C:P/A:N/I:P/B:N");
  script_tag(name:"risk_factor", value:"Medium");
  name = "Multiple phpShop Vulnerabilities";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
 
  summary = "Detect phpShop SQL Injection";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");

  family = "Web application abuses";
  script_family(family);
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/350026");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/?page=shop/cart&func=cartAdd&product_id='"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 #find = string("You have an error in your SQL syntax near ");
 find = ".*SQL.*item_enquiry_details.*auth=a";
 if (egrep(pattern:find, string:res))
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir (cgi_dirs()) check_dir(path:dir);
