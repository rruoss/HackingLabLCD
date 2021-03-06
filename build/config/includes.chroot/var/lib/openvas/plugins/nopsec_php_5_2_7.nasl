##############################################################################
# OpenVAS Vulnerability Test
# $Id: nopsec_php_5_2_7.nasl.nasl 110172
# 2012-07-02 11:43:12 +0100 (Mon, 02 Jul 2012) $
# 
# PHP smaller than 5.2.7
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
tag_solution = "Update PHP to version 5.2.7 or later.";
tag_summary = "PHP version smaller than 5.2.7 suffers vulnerability.";

if (description)
{
  script_id(110172);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)");
  script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");

    script_cve_id(
    "CVE-2008-2371",
    "CVE-2008-2665",
    "CVE-2008-2666",
    "CVE-2008-2829",
    "CVE-2008-3658",
    "CVE-2008-3659",
    "CVE-2008-3660",
    "CVE-2008-5557",
    "CVE-2008-5624",
    "CVE-2008-5625",
    "CVE-2008-5658"
  );
  script_bugtraq_id(
    29796,
    29797,
    29829,
    30087,
    30649,
    31612,
    32383,
    32625,
    32688,
    32948
    # 33498         nb: retired 29-Jan-2009
  );
script_name("PHP version smaller than 5.2.7");
  script_summary("Checks PHP Version");

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_category(ACT_GATHER_INFO);
  script_description(desc);
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

my_port=get_http_port(default:80);

if(get_port_state(my_port))
{
  php_version=get_kb_item(string("www/", my_port, "/PHP"));
  if (isnull(php_version)) exit(0);
  if (version_is_less(version:php_version,test_version:"5.2.7"))
  security_hole(port:my_port);
  exit(0);
}
exit(0);
