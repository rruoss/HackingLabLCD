###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_proxy_server_dos_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun Java System Web Proxy Server Denial Of Service Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Apply patch 141248-01 or later
  http://sunsolve.sun.com/search/document.do?assetkey=1-21-141248-01-1

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will allow attackers to cause a Denial of Service
  in the context of an affected application.
  Impact Level: Application";
tag_affected = "Sun Java System Access Manager Policy Agent version 2.2
  Sun Java System Web Proxy Server version 4.0.x on Linux.";
tag_insight = "The flaw is due to an unspecified error, which can be exploited to
  cause a crash via a 'GET' request, if the Sun Java System Web Proxy Server is
  the used deployment container for the agent.";
tag_summary = "This host has Java Web Proxy Server running, which is prone to
  Denial of Service vulnerability.";

if(description)
{
  script_id(800866);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-12 19:54:51 +0200 (Wed, 12 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2597");
  script_bugtraq_id(35788);
  script_name("Sun Java System Web Proxy Server Denial Of Service Vulnerability (Linux)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/35979/");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-258508-1");

  script_description(desc);
  script_summary("Check for the version of Web Proxy Server and AM Policy Agent");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_sun_java_sys_web_proxy_server_detect.nasl");
  script_require_keys("Sun/JavaWebProxyServ/Ver", "Sun/JavaWebProxyServ/Port");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

if(get_kb_item("Sun/JavaWebProxyServ/Ver") >!< "4.0"){
  exit(0);
}

sun_sock = ssh_login_or_reuse_connection();
if(!sun_sock){
  exit(0);
}

paths = find_file(file_name:"config_linux", file_path:"/proxy4/bin/",
                  useregex:TRUE, regexpar:"$", sock:sun_sock);

foreach agentBin (paths)
{
  #Grep for Access Manager Policy Agent Version
  agentVer = get_bin_version(full_prog_name:"cat", version_argv:chomp(agentBin),
                            ver_pattern:"proxy4agent-([0-9.]+)", sock:sun_sock);

  
  if(!isnull(agentVer[1]))
  {
    # Check for Access Manager Policy Agent Version
    if(version_is_equal(version:agentVer[1], test_version:"2.2"))
    {
      sun_port = get_kb_item("Sun/JavaWebProxyServ/Port");
      security_hole(sun_port);
      exit(0);
    }
  }
}