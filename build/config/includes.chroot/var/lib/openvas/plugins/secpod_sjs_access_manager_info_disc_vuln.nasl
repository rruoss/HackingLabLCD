###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sjs_access_manager_info_disc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun Java System Access Manager Information Disclosure vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_solution = "Apply the security updates.
  http://sunsolve.sun.com/search/document.do?assetkey=1-21-126356-03-1

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation could allow remote unprivileged user to gain the
  sensitive information.
  Impact Level: Application";
tag_affected = "Java System Access Manager version 7.0 2005Q4 and 7.1";
tag_insight = "Error in CDCServlet component is caused when 'Cross Domain Single Sign On'
  (CDSSO) is enabled which does not ensure that 'policy advice' is presented
  to the correct client, which can be exploited via unspecified vectors.";
tag_summary = "The host is running Java System Access Manager and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_id(900195);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2713");
  script_bugtraq_id(35961);
  script_name("Sun Java System Access Manager Information Disclosure vulnerability");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/36167");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2176");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-255968-1");

  script_description(desc);
  script_summary("Check for the version of Java System Access Manager");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_sjs_access_manager_detect.nasl");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

am_port = get_http_port(default:8080);
if(!am_port){
  am_port = 8080;
}

amVer = get_kb_item("www/" + am_port + "/Sun/JavaSysAccessMang");
amVer = eregmatch(pattern:"^(.+) under (/.*)$", string:amVer);

# Check for Java Access Manager version 7.0 2005Q4 or 7.1
if(amVer[1] =~ "7.1|7.0.2005Q4"){
  security_warning(am_port);
}
