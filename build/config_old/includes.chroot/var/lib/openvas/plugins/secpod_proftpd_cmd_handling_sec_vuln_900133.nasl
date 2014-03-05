##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_proftpd_cmd_handling_sec_vuln_900133.nasl 16 2013-10-27 13:09:52Z jan $
# Description: ProFTPD Long Command Handling Security Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_impact = "This can be exploited to execute arbitrary FTP commands on another
  user's session privileges.
  Impact Level : Application";

tag_solution = "Fixed is available in the SVN repository,
  http://www.proftpd.org/cvs.html

  *****
  NOTE : Ignore this warning, if above mentioned fix is applied already.
  *****";

tag_affected = "ProFTPD Project versions 1.2.x on Linux
  ProFTPD Project versions 1.3.x on Linux";

tag_insight = "The flaw exists due to the application truncating an overly long FTP command,
  and improperly interpreting the remainder string as a new FTP command.";


tag_summary = "The host is running ProFTPD Server, which is prone to cross-site
  request forgery vulnerability.";


if(description)
{
  script_id(900133);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-09-26 07:36:49 +0200 (Fri, 26 Sep 2008)");
  script_cve_id("CVE-2008-4242");
 script_bugtraq_id(31289);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_name("ProFTPD Long Command Handling Security Vulnerability");
  script_summary("Check for vulnerable version of ProFTPD Project");
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
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/31930/");
  script_xref(name : "URL" , value : "http://bugs.proftpd.org/show_bug.cgi?id=3115");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

banner = get_ftp_banner(port:port);
if("ProFTPD" >!< banner){
  exit(0);
}
 
if(egrep(pattern:"ProFTPD 1\.(2(\..*)?|3(\.0|\.1(rc[0-3])?[^rc])?)[^.0-9]",
         string:banner)){
  security_hole(port);
}
