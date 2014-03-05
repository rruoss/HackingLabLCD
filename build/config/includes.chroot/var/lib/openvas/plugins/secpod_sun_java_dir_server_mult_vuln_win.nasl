###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_java_dir_server_mult_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Sun Java System DSEE Multiple Vulnerabilities (Win)
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
tag_solution = "Apply patch 141958-01 or later for Sun Java System DSEE version 6.3.1
  http://sunsolve.sun.com/search/document.do?assetkey=1-21-141958-01-1

  *****
  NOTE: Ignore this warning if patch is applied already.
  *****";

tag_impact = "Successful exploitation will allow attacker to gain knowledge of potentially
  sensitive information or cause a Denial of Service.
  Impact Level: Application";
tag_affected = "Sun Java System DSEE version 6.0 through 6.3.1 on Windows.";
tag_insight = "- An error in Directory Proxy Server may cause a client operation to
    temporarily run with another client's privileges.
  - An error in Directory Proxy Server can be exploited via specially crafted
    packets to cause the service to stop responding to new client connections.
  - An error in Directory Proxy Server can be exploited via a specially crafted
   'psearch' client to exhaust available CPU resources, preventing the server
    from sending results to other 'psearch' clients.";
tag_summary = "This host is running Sun Java System Directory Server Enterprise
  Edition (DSEE) and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(902011);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-04 15:26:56 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4440", "CVE-2009-4441", "CVE-2009-4442", "CVE-2009-4443");
  script_bugtraq_id(37481);
  script_name("Sun Java System DSEE Multiple Vulnerabilities (Win)");
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
  script_summary("Check for the version of Sun Java System DSEE");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_sun_java_dir_server_detect_win.nasl");
  script_require_keys("Sun/JavaDirServer/Win/Ver");
  script_require_ports("Services/www", 1389, 389);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37915/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3647");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-270789-1");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

foreach dseePort (make_list("1389", "389"))
{
  if(get_port_state(dseePort))
  {
    sndReq = http_get(item:string("/"), port:dseePort);
    rcvRes = http_send_recv(port:dseePort, data:sndReq);
    if("Directory Server" >< rcvRes)
    {
      ver = get_kb_item("Sun/JavaDirServer/Win/Ver");
      # Check for Sun Java System DSEE version 6.0 to 6.3.1
      if(version_in_range(version:ver, test_version:"6.0", test_version2:"6.3.1"))
      {
        security_hole(dseePort);
        exit(0);
      }
    }
  }
}
