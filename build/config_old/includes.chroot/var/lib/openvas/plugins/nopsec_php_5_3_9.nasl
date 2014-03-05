##############################################################################
# OpenVAS Vulnerability Test
# $Id: nopsec_php_5_3_9.nasl 110012 
#2012-06-18 11:43:12 +0100 (Mon, 18 Jun 2012) $
#
# PHP versoin < 5.3.9 
#
# Authors:
# Songhan Yu <syu@nopsec.com>
#
# Copyright:
# Copyright NopSec Inc. 2012, http://www.nopsec.com
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
tag_solution = "Upgrate PHP to 5.3.9 or versions after.";
tag_summary = "PHP versoin < 5.3.9 suffers multiple vulnerabilities such as DOS bysendign crafted requests including hash collision parameter values. Several errors exist in some certain functions as well.";

if (description)
{
   script_id(110012);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-06-14 13:15:22 +0200 (Thu, 14 Jun 2012)");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_cve_id( "CVE-2011-4566", "CVE-2011-4885", "CVE-2012-0057", "CVE-2012-0781", "CVE-2012-0788", "CVE-2012-0789"
  );
  script_bugtraq_id(50907, 51193, 51806, 51952, 51992, 52043);

  script_name("PHP versoin < 5.3.9 ");
  script_summary("Check the version of PHP");

  desc = "
   Summary:
   " + tag_summary + "
   Solution:
   " + tag_solution;
  script_description(desc);

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_copyright("Copyright NopSec Inc. 2012");

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

if(report_paranoia < 2) exit(0);
my_port=get_http_port(default:80);

if(get_port_state(my_port))
{
  php_version=get_kb_item(string("www/", my_port, "/PHP"));
  if (isnull(php_version)) exit(0);
  if (version_is_less(version:php_version,test_version:"5.3.9"))
  security_hole(port:my_port);
  exit(0);
}
exit(0);















