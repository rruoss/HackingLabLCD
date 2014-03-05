###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_sim_unauth_access_vuln_lin.nasl 16 2013-10-27 13:09:52Z jan $
#
# HP Systems Insight Manager Unauthorized Access Vulnerability (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could allow remote attackers to gain unauthorized
  access to the data.
  Impact Level: Application";
tag_affected = "HP SIM prior to 5.2 with Update 2 (C.05.02.02.00) on Linux";
tag_insight = "The flaw is due to an error in the application which allows unauthorized
  access to certain data.";
tag_solution = "Update to HP SIM version 5.2 with Update 2 (C.05.02.02.00)
  http://h20392.www2.hp.com/portal/swdepot/index.do";
tag_summary = "This host is running HP Systems Insight Manager (SIM) and is prone
  to security bypass vulnerability.";

if(description)
{
  script_id(800034);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-21 16:25:40 +0200 (Tue, 21 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-4412");
  script_bugtraq_id(31777);
  script_name("HP Systems Insight Manager Unauthorized Access Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32287/");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01571962");

  script_description(desc);
  script_summary("Check for the version of HP SIM");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
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
include("version_func.inc");

port = 50000;;
if(!port){
  exit(0);
}

if(!get_port_state(port)){
  exit(0);
}

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

simName = find_file(file_name:"mxversion", file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:sock);
foreach binaryName(simName)
{
  simVer = get_bin_version(full_prog_name:chomp(binaryName), sock:sock,
                          ver_pattern:"Linux ([^ ]+)");
  if(simVer)
  {
    # Grep for versions prior to 5.2 with update 2 (C.05.02.02.00)
    if(version_is_less(version:simVer[1], test_version:"C.05.02.02.00"))
    {
      security_warning(port);
      ssh_close_connection();
      exit(0);
    }
  }
}
ssh_close_connection();
