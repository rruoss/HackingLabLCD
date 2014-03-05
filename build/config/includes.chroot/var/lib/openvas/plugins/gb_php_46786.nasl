###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_46786.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP 'shmop_read()' Remote Integer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "PHP is prone to an integer-overflow vulnerability because it
fails to ensure that integer values are not overrun.

Successful exploits of this vulnerability allow remote attackers to
execute arbitrary code in the context of a webserver affected by the
issue. Failed attempts will likely result in denial-of-service
conditions.

Versions prior to PHP 5.3.6 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103113);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-09 13:38:24 +0100 (Wed, 09 Mar 2011)");
 script_bugtraq_id(46786);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-1092");

 script_name("PHP 'shmop_read()' Remote Integer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed php version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_php_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("php/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46786");
 script_xref(name : "URL" , value : "http://comments.gmane.org/gmane.comp.security.oss.general/4436");
 script_xref(name : "URL" , value : "http://www.php.net/");
 script_xref(name : "URL" , value : "http://svn.php.net/viewvc/?view=revision&amp;revision=309018");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!vers = get_kb_item(string("www/", port, "/PHP")))exit(0);

if(!isnull(vers)) {

  if(version_in_range(version: vers, test_version: "5", test_version2: "5.3.6")) {
      security_hole(port:port);
      exit(0);
  }


}

