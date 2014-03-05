###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_dos_vuln_feb10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Squid 'lib/rfc1035.c' Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updataed By:
# Antu Sanadi <santu@secpod.com> on 2010-02-16
# included the port check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Apply patches or upgrade to the squid version 3.0.STABLE23 or 3.1.0.16
  http://www.squid-cache.org/Download/
  http://www.squid-cache.org/Versions/v2/HEAD/changesets/12597.patch
  http://www.squid-cache.org/Versions/v3/3.0/changesets/squid-3.0-9163.patch
  http://www.squid-cache.org/Versions/v3/3.1/changesets/squid-3.1-9853.patch

  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to cause a denial of service
  via a crafted auth header.";
tag_affected = "Squid Version 2.x, 3.0 to 3.0.STABLE22, and  3.1 to 3.1.0.15";
tag_insight = "The flaw is due to error in 'lib/rfc1035.c' when, processing crafted DNS
  packet that only contains a header.";
tag_summary = "This host is running Squid and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(800460);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-0308");
  script_name("Squid 'lib/rfc1035.c' Denial Of Service Vulnerability");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/38455");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38451");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56001");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0260");
  script_xref(name : "URL" , value : "http://www.squid-cache.org/Advisories/SQUID-2010_1.txt");

  script_description(desc);
  script_summary("Check for the version of Squid");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

port = 3128;
if(!get_port_state(port)){
  port = 8080;
}

squidVer = get_kb_item(string("www/", port, "/Squid"));
if(isnull(squidVer)){
  exit(0);
}

if((squidVer =~ "^2\.0") ||
    version_in_range(version:squidVer, test_version:"3.1", test_version2:"3.1.0.15") ||
    version_in_range(version:squidVer, test_version:"3.0", test_version2:"3.0.STABLE22")){
  security_warning(port);
}
