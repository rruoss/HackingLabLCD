##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_edirectory_session_hijack_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Novell eDirectory 'DHOST' Cookie Hijack Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to hijack arbitrary
  sessions.
  Impact Level: Application.";
tag_affected = "Novell eDirectory version 8.8.5 and prior.";

tag_insight = "The flaw is due to error in an 'DHOST' module when handling DHOST web
  services.An attacker would wait until the real administrator logs in, then
  specify the predicted cookie value to hijack their session.";
tag_solution = "No solution or patch is available as of 05th March 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.novell.com/products/edirectory/";
tag_summary = "This host is running Novell eDirectory is prone to Session Cookie
  hijack vulnerability.";

if(description)
{
  script_id(800731);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4655");
  script_name("Novell eDirectory 'DHOST' Cookie Hijack Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/60035");
  script_xref(name : "URL" , value : "http://www.metasploit.com/modules/auxiliary/admin/edirectory/edirectory_dhost_cookie");

  script_description(desc);
  script_summary("Check for the version of Novell eDirectory");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("novell_edirectory_detect.nasl");
  script_require_ports("Services/ldap", 389);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");

port = get_kb_item("Services/ldap");
if(!port){
  exit(0);
}

if(!get_port_state(port)){
  exit(0);
}

edirVer = get_kb_item(string("ldap/", port,"/eDirectory"));
if(isnull(edirVer)){
 exit(0);
}

edirVer = eregmatch(pattern:"(([0-9.]+).?([a-zA-Z0-9]+)?)", string:edirVer);
if(!isnull(edirVer[1]))
{
  edirVer = ereg_replace(pattern:"-| ", replace:".", string:edirVer[1]);
  if(version_in_range(version:edirVer, test_version:"8.8", test_version2:"8.8.5")){
    security_hole(port);
  }
}
