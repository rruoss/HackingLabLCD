##############################################################################
# OpenVAS Vulnerability Test
# $Id: nopsec_php_5_2_1.nasl.nasl 110175
# 2012-07-02 11:43:12 +0100 (Mon, 02 Jul 2012) $
# 
# PHP smaller than 5.2.1
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
tag_solution = "Update PHP to version 5.2.1 or later.";
tag_summary = "PHP version smaller than 5.2.1 suffers vulnerability.";

if (description)
{
  script_id(110175);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)");
  script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");

    script_cve_id(
    "CVE-2006-6383",
    "CVE-2007-0905",
    "CVE-2007-0906",
    "CVE-2007-0907",
    "CVE-2007-0908",
    "CVE-2007-0909",
    "CVE-2007-0910",
    "CVE-2007-0988",
    "CVE-2007-1376",
    "CVE-2007-1380",
    "CVE-2007-1383",
    "CVE-2007-1452",
    "CVE-2007-1453",
    "CVE-2007-1454",
    "CVE-2007-1700",
    "CVE-2007-1701",
    "CVE-2007-1824",
    "CVE-2007-1825",
    "CVE-2007-1835",
    "CVE-2007-1884",
    "CVE-2007-1885",
    "CVE-2007-1886",
    "CVE-2007-1887",
    "CVE-2007-1889",
    "CVE-2007-1890",
    "CVE-2007-4441",
    "CVE-2007-4586"
  );
  script_bugtraq_id(
    21508, 
    22496, 
    22805,
    22806,
    22862,
    22922,
    23119,
    23120,
    23219,
    23233, 
    23234, 
    23235, 
    23236, 
    23237, 
    23238
  );
script_name("PHP version smaller than 5.2.1");
  script_summary("Checks PHP Version");

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
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

my_port=get_http_port(default:80);

if(get_port_state(my_port))
{
  php_version=get_kb_item(string("www/", my_port, "/PHP"));
  if (isnull(php_version)) exit(0);
  if (version_is_less(version:php_version,test_version:"5.2.1"))
  security_hole(port:my_port);
  exit(0);
}
exit(0);
