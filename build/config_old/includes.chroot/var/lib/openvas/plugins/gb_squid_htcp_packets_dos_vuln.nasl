###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_htcp_packets_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Squid HTCP Packets Processing Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_solution = "Apply patches or upgrade to the squid version 3.0.STABLE24
  http://www.squid-cache.org/Download/
  http://www.squid-cache.org/Versions/v2/2.7/changesets/12600.patch
  http://www.squid-cache.org/Versions/v3/3.0/changesets/3.0-ADV-2010_2.patch

  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to crash an affected
  server, creating a denial of service condition.";
tag_affected = "Squid Version 2.x, and 3.0 to 3.0.STABLE23";
tag_insight = "The flaw is due to error in 'htcpHandleTstRequest()' function in 'htcp.c', when
  processing malformed HTCP (Hypertext Caching Protocol) packets.";
tag_summary = "This host is running Squid and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(800473);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-0639");
  script_bugtraq_id(38212);
  script_name("Squid HTCP Packets Processing Denial of Service Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0371");
  script_xref(name : "URL" , value : "http://www.squid-cache.org/Advisories/SQUID-2010_2.txt");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Feb/1023587.html");

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

if((squidVer =~ "^2\.*") ||
    version_in_range(version:squidVer, test_version:"3.0", test_version2:"3.0.STABLE23")){
  security_warning(port);
}
