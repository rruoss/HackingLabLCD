##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zikula_sec_bypass_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Zikula Security bypass Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to defeat protection
  mechanisms based on randomization by predicting a return value.
  Impact Level: Application.";
tag_affected = "Zikula version prior to 1.3.1";

tag_insight = "The flaw exists due to errors in 'rand' and 'srand' PHP functions for random
  number generation";
tag_solution = "Upgrade to the Zikula version 1.3.1
  For updates refer to http://zikula.org/";
tag_summary = "This host is running Zikula and is prone to security bypass
  vulnerability.";

if(description)
{
  script_id(801744);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_cve_id("CVE-2010-4728");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Zikula Security bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://code.zikula.org/core/ticket/2009");

  script_description(desc);
  script_summary("Check for the version of Zikula");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_zikula_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

zkPort = get_http_port(default:80);
if(!get_port_state(zkPort)){
  exit(0);
}

## Get Zikula version from KB
if(!zkVer = get_version_from_kb(port:zkPort,app:"zikula")){
  exit(0);
}

if(version_is_less(version:zkVer, test_version:"1.3.1")){
  security_warning(port:zkPort);
}
