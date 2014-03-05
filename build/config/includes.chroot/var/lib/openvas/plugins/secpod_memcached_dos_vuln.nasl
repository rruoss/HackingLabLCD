###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_memcached_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Memcached Denial of service vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to cause a denial of service.
  Impact Level: Application";
tag_affected = "Memcached 1.4.2 and prior";
tag_insight = "The flaw is due to error in try_read_command() function that allows attacker
  to temporarily hang or potentially crash the server by sending an overly
  large number of bytes.";
tag_solution = "Upgrade to the latest version of Memcached 1.4.3 or later,
  For updates refer to http://memcached.org";
tag_summary = "The host is running Memcached and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(901103);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_cve_id("CVE-2010-1152");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Memcached Denial of service vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39306");
  script_xref(name : "URL" , value : "http://code.google.com/p/memcached/issues/detail?id=102");

  script_description(desc);
  script_summary("Check for the version of Memcached");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_memcached_detect.nasl");
  script_require_keys("MemCached/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

memPort = 11211;
if(!get_port_state(memPort)){
  exit(0);
}

memVer = get_kb_item("MemCached/Ver");
if(memVer == NULL){
  exit(0);
}

## Grep for Memcached version prior to 1.4.3
if(version_is_less(version:memVer, test_version:"1.4.3")){
  security_warning(memPort);
}
