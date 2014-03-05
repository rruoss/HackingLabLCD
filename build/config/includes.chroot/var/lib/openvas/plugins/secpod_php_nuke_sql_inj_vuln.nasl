###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_nuke_sql_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP-Nuke Sections Module SQL Injection Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  sensitive information about the database used by the web application or can cause
  arbitrary code execution inside the context of the web application.
  Impact Level: Application";
tag_affected = "PHP-Nuke version prior to 8.0";
tag_insight = "The flaw is due to improper sanitization of user supplied input through the
  'artid' parameter in a printable action to modules.php";
tag_solution = "Upgrade to PHP-Nuke version 8.0 or later
  http://phpnuke-downloads.com/phpnuke.html";
tag_summary = "This host is running PHP-Nuke and is prone to SQL Injection
  vulnerability.";

if(description)
{
  script_id(900339);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-6728");
  script_bugtraq_id(27958);
  script_name("PHP-Nuke Sections Module SQL Injection Vulnerability");
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


  script_description(desc);
  script_summary("Check for the version of PHP-Nuke");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_php_nuke_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/52033");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/488653");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/499687");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/data/vulnerabilities/exploits/27958.php");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

nukePort = get_http_port(default:80);
if(!nukePort){
  exit(0);
}

nukeVer = get_kb_item("www/"+ nukePort + "/php-nuke");
if(!nukeVer){
  exit(0);
}

ver = eregmatch(pattern:"^(.+) under (/.*)$", string:nukeVer);
if(ver[1] != NULL)
{
  # Check for PHP-Nuke version prior to 8.0
  if(version_is_less(version:ver[1], test_version:"8.0")){
    security_hole(nukePort);
  }
}
