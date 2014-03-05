##############################################################################
# OpenVAS Vulnerability Test
# $Id: nopsec_php_5_2_15.nasl 110066 
# 2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012) $
#
# PHP 5.2 < 5.2.15
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
tag_summary = "PHP 5.2 < 5.2.15 suffers multiple vulnerabilities such as crash in the zip extract method, NULL pointer dereference and stack-based buffer overfLow.
Upgrade to PHP version 5.2.15 or later.";

if (description)
{
  script_id(110066);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)");
  script_tag(name:"risk_factor", value:"High");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"cvss_base", value:"6.8");
  script_cve_id(
    "CVE-2010-3436",
    "CVE-2010-3709",
    "CVE-2010-4150",
    "CVE-2010-4697",
    "CVE-2010-4698",
    "CVE-2011-0752"
  );
  script_bugtraq_id(44718, 44723, 45335, 45952, 46448);

  script_name("PHP 5.2 < 5.2.15 ");
  script_summary("Checks version of PHP");

  desc = "
  Summary:
  " + tag_summary;
 
  script_description(desc);
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_copyright("Copyright NopSec Inc. 2012");

  script_dependencies("gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("php/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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
  if (version_in_range(version:php_version,test_version:"5.2", test_version2:"5.2.15"))
  security_hole(port:my_port);
  exit(0);
}
exit(0);