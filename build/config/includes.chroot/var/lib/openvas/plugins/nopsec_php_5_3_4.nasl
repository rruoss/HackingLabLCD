##############################################################################
# OpenVAS Vulnerability Test
# $Id: nopsec_php_5_3_4.nasl.nasl 110181
# 2012-07-02 11:43:12 +0100 (Mon, 02 Jul 2012) $
# 
# PHP smaller than 5.3.4
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
tag_solution = "Update PHP to version 5.3.4 or later.";
tag_summary = "PHP version smaller than 5.3.4 suffers vulnerability.";

if (description)
{
  script_id(110181);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)");
  script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");

    script_cve_id(
    "CVE-2006-7243",
    "CVE-2010-2094",
    "CVE-2010-2950",
    "CVE-2010-3436",
    "CVE-2010-3709",
    "CVE-2010-3710",
    "CVE-2010-3870",
    "CVE-2010-4150",
    "CVE-2010-4156",
    "CVE-2010-4409",
    "CVE-2010-4697",
    "CVE-2010-4698",
    "CVE-2010-4699",
    "CVE-2010-4700",
    "CVE-2011-0753",
    "CVE-2011-0754",
    "CVE-2011-0755"
  );
  script_bugtraq_id(
    40173,
    43926,
    44605,
    44718,
    44723,
    44951,
    44980,
    45119,
    45335,
    45338,
    45339,
    45952,
    45954,
    46056,
    46168
  );
script_name("PHP version smaller than 5.3.4");
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
  if (version_is_less(version:php_version,test_version:"5.3.4"))
  security_hole(port:my_port);
  exit(0);
}
exit(0);
