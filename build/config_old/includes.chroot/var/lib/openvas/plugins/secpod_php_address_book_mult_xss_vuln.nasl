##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_address_book_mult_xss_vuln.nasl 72 2013-11-21 17:10:44Z mime $
#
# PHP Address Book Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "PHP Address Book 7.0 and prior";
tag_insight = "Multiple flaws are caused by improper validation of user supplied input by the
  'preferences.php', 'group.php', 'index.php' and 'translate.php' scripts, which
  allows attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site.";
tag_solution = "No solution or patch is available as of 24th May, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/php-addressbook/";
tag_summary = "This host is running PHP Address Book and is prone to multiple
  cross site scripting vulnerabilities.";

if(description)
{
  script_id(902838);
  script_version("$Revision: 72 $");
  script_bugtraq_id(53598);
  script_cve_id("CVE-2012-2903");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-11-21 18:10:44 +0100 (Thu, 21 Nov 2013) $");
  script_tag(name:"creation_date", value:"2012-05-24 15:15:15 +0530 (Thu, 24 May 2012)");
  script_name("PHP Address Book Multiple Cross Site Scripting Vulnerabilities");
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
  script_summary("Check if PHP Address Book is vulnerable to cross site scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_php_address_book_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("PHP-Address-Book/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/81986");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49212");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75703");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18899");
  script_xref(name : "URL" , value : "http://sourceforge.net/tracker/?func=detail&amp;aid=3527242&amp;group_id=157964&amp;atid=805929");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Variable Initialization
dir = "";
url = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get PHP Address Book Location
if(!dir = get_dir_from_kb(port:port, app:"PHP-Address-Book")){
  exit(0);
}

## Construct attack request
url = dir + '/index.php?group="<script>alert(document.cookie)</script>';

## Try XSS and check the response to confirm vulnerability
if(http_vuln_check( port: port, url: url, check_header: TRUE,
                    pattern: "<script>alert\(document.cookie\)</script>",
                    extra_check: 'content=\"PHP-Addressbook')) {
  security_warning(port);
}
