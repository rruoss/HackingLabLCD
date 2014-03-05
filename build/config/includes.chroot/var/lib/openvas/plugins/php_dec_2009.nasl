###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_dec_2009.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP < 5.2.12 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "PHP is prone to a cross-site scripting vulnerability and to a code
execution vulnerability.

Attackers can exploit the code execution vulnerability to execute
arbitrary code within the context of the PHP process. This may allow
them to bypass intended security restrictions or gain elevated
privileges. 

An attacker may leverage the cross-site scripting vulnerability to
execute arbitrary script code in the browser of an unsuspecting user
in the context of the affected site. This may let the attacker steal
cookie-based authentication credentials and launch other attacks.

Versions prior to PHP 5.2.12 are vulnerable.";

tag_solution = "Updates are available; please see the references for more information.";

if (description)
{
 script_id(100409);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-18 16:46:00 +0100 (Fri, 18 Dec 2009)");
 script_bugtraq_id(37390,37389);
 script_cve_id("CVE-2009-4143","CVE-2009-4142");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 script_name("PHP < 5.2.12 Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37390");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37389");
 script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php#5.2.12");
 script_xref(name : "URL" , value : "http://www.php.net/releases/5_2_12.php");
 script_xref(name : "URL" , value : "http://www.php.net");
 script_xref(name : "URL" , value : "http://www.suspekt.org/downloads/POC2009-ShockingNewsInPHPExploitation.pdf");
 script_xref(name : "URL" , value : "http://www.blackhat.com/presentations/bh-usa-09/ESSER/BHUSA09-Esser-PostExploitationPHP-PAPER.pdf");
 script_xref(name : "URL" , value : "http://d.hatena.ne.jp/t_komura/20091004/1254665511");
 script_xref(name : "URL" , value : "http://bugs.php.net/bug.php?id=49785");

 script_description(desc);
 script_summary("Determine if php version is < 5.2.12");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_php_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("php/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

if(!vers = get_kb_item(string("www/", port, "/PHP")))exit(0);

if(!isnull(vers)) {

  if(vers =~ "^5\.2") {
    if(version_is_less(version: vers, test_version: "5.2.12")) {
      security_hole(port:port);
      exit(0);
    }
  }
}

exit(0);

