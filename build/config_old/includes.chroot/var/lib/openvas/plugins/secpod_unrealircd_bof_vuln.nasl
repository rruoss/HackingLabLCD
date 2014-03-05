###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_unrealircd_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# UnrealIRCd Buffer Overflow Vulnerability
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
tag_solution = "Upgrade to UnrealIRCd version 3.2.8.1 or later,
  For updates refer to http://www.unrealircd.com/downloads.php

  Workaround: Remove noident from the allow::options and /REHASH.

  *****
  NOTE: Ignore this warning, if allow::options::noident is not enabled.
  *****";

tag_impact = "Successful exploitation will allow attacker to cause a denial of service
  and possibly execute arbitrary code via unspecified vectors.
  Impact Level: Application";
tag_affected = "UnrealIRCd version 3.2beta11 through 3.2.8";
tag_insight = "The flaw is caused by an error when allow::options::noident is enabled,
  which allows remote attackers to cause a denial of service and possibly
  execute arbitrary code via unspecified vectors.";
tag_summary = "This host is running UnrealIRCd and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(901126);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2009-4893");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("UnrealIRCd Buffer Overflow Vulnerability");
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

  script_xref(name : "URL" , value : "http://security.gentoo.org/glsa/glsa-201006-21.xml");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/06/14/13");
  script_xref(name : "URL" , value : "http://www.unrealircd.com/txt/unrealsecadvisory.20090413.txt");

  script_description(desc);
  script_summary("Check for the vulnerable version of UnrealIRCd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl","ircd.nasl");
  script_require_ports("Services/irc", 6667);
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

## Get IRC port
port = get_kb_item("Services/irc");
if (!port){
  port = 6667;
}

## Check port status
if(!get_port_state(port)){
   exit(0);
}

## Get Banner
banner = get_kb_item(string("irc/banner/", port));
if(isnull(banner)){
  exit(0);
}

## Confirm Application
if("unreal" >< tolower(banner))
{
  ## Get Version from Banner
  ver = eregmatch(pattern:"[u|U]nreal([0-9.]+)", string:banner);

  ## Check for vulnerable versions
  if(version_in_range (version: ver[1], test_version: "3.2", test_version2: "3.2.8") ){
    security_hole(port);
  }
}
