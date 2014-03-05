###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_squid_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Squid External Auth Header Parser DOS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to cause a denial of service
  via a crafted auth header with certain comma delimiters that trigger an infinite
  loop of calls to the strcspn function.";
tag_affected = "Squid Version 2.7.X";
tag_insight = "The flaw is due to error in 'strListGetItem()' function within
  'src/HttpHeaderTools.c'.";
tag_solution = "Upgrade to Squid Version 3.1.4 or later,
  For further updates refer, http://www.squid-cache.org/Download/";
tag_summary = "This host is running Squid and is  prone to Denial Of
  Service vulnerabilities.";

if(description)
{
  script_id(101105);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-24 07:49:31 +0200 (Mon, 24 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2855");
  script_name("Squid External Auth Header Parser DOS Vulnerabilities");
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


  script_description(desc);
  script_summary("Check for the version of Squid");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.squid-cache.org/bugs/show_bug.cgi?id=2704");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/08/03/3");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534982");
  exit(0);
}


include("version_func.inc");

port = 3128;
if(!get_port_state(port)){
  port = 8080;
}

if(!get_port_state(port)){
  exit(0);
}

squidVer =get_kb_item(string("www/", port, "/Squid"));
if((squidVer != NULL) && (squidVer =~ "^2\.7")){
  security_warning(port);
}
