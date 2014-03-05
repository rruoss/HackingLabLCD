###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_address_book_sql_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP Address Book Multiple SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the attacker cause SQL Injection attack, gain
  sensitive information about the database used by the web application.
  Impact Level: Application";
tag_affected = "PHP Address Book version 4.0.x";
tag_insight = "The flaw is due to improper sanitization of user supplied input passed to the
  'id' parameter in view.php, edit.php, and delete.php, and to the 'alphabet'
  parameter in index.php before being used in SQL queries.";
tag_solution = "Upgrade to PHP Address Book version 5.7.2 or later,
  For updates refer to http://sourceforge.net/projects/php-addressbook/";
tag_summary = "This host is running PHP Address Book and is prone to SQL Injection
  vulnerability.";

if(description)
{
  script_id(900698);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2608");
  script_bugtraq_id(35511);
  script_name("PHP Address Book Multiple SQL Injection Vulnerabilities");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35590");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9023");

  script_description(desc);
  script_summary("Check for the version of PHP-Nuke");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_php_address_book_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");

phpPort = get_http_port(default:80);
if(!phpPort){
  exit(0);
}

phpVer = get_kb_item("www/"+ phpPort + "/PHP-Address-Book");
if(!phpVer){
  exit(0);
}

ver = eregmatch(pattern:"^(.+) under (/.*)$", string:phpVer);
if(ver[1] =~ "^4\.0"){
  security_hole(phpPort);
}
