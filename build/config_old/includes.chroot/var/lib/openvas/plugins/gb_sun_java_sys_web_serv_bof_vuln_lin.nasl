###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_bof_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun Java System Web Server Buffer Overflow Vulnerability (Linux)
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
tag_impact = "Successful exploitation lets the attackers to execute arbitrary code
  in the context of an affected system.
  Impact Level: System/Application";
tag_affected = "Sun Java System Web Server version 7.0 update 6 and prior on Linux.";
tag_insight = "An unspecified error that can be exploited to cause a buffer overflow.";
tag_solution = "No solution or patch is available as of 10th November, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.sun.com/";
tag_summary = "This host has Sun Java Web Server running which is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_id(801147);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-12 15:21:24 +0100 (Thu, 12 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3878");
  script_bugtraq_id(36813);
  script_name("Sun Java System Web Server Buffer Overflow Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://intevydis.com/vd-list.shtml");
  script_xref(name : "URL" , value : "http://www.intevydis.com/blog/?p=79");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37115");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3024");

  script_description(desc);
  script_summary("Check for the version of Java System Web Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 80, 8888, 8989);
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");
include("http_func.inc");
include("version_func.inc");

foreach jswsPort (make_list(8989, 8888, 80))
{
  if(get_port_state(jswsPort))
  {
    jswsSock = ssh_login_or_reuse_connection();
    if(!jswsSock){
      exit(0);
    }

    paths = find_file(file_name:"webservd", file_path:"/", useregex:TRUE,
                      regexpar:"$", sock:jswsSock);
    foreach jswsBin (paths)
    {
      ver = get_bin_version(full_prog_name:chomp(jswsBin), sock:jswsSock,
                            version_argv:"-v",
                            ver_pattern:"Sun (ONE |Java System )Web Server " +
                                        "([0-9.]+)(SP|U)?([0-9]+)?([^0-9.]|$)");
      if(ver[2] != NULL)
      {
        if(ver[4] != NULL)
          ver = ver[2] + "." + ver[4];
        else
          ver = ver[2];

        # Check for Web Server version <= 7.0 Update 6
        if(version_is_less_equal(version:ver, test_version:"7.0.6"))
        {
          security_hole(jswsPort);
          exit(0);
        }
      }
    }
  }
}
ssh_close_connection();
