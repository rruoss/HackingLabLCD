###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_filezilla_server_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# FileZilla Server Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker crash the application to
  cause denial of service.";
tag_affected = "FileZilla Server versions prior to 0.9.31";
tag_insight = "The flaw is generated due to an error in unspecified vectors while
  handling SSL/TLS packets.";
tag_solution = "Upgrade to FileZilla Server version 0.9.31
  http://filezilla-project.org/index.php";
tag_summary = "This host is running FileZilla Server and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(900519);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 08:26:42 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0884");
  script_bugtraq_id(34006);
  script_name("FileZilla Server Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34089");
  script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?release_id=665428");

  script_description(desc);
  script_summary("Check for the version of FileZilla Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_filezilla_server_detect.nasl");
  script_require_keys("FileZilla/Serv/Ver");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

fzillaPort = get_kb_item("Services/ftp");
if(!fzillaPort){
  exit(0);
}

filezillaVer = get_kb_item("FileZilla/Serv/Ver");
if(!filezillaVer){
  exit(0);
}

if(version_is_less(version:filezillaVer, test_version:"0.9.31")){
  security_warning(fzillaPort);
}
