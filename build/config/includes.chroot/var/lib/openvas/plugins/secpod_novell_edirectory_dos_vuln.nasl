##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_edirectory_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Novell eDirectory NCP Request Remote Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to cause a vulnerable
  service to become unresponsive, leading to a denial of service condition.
  Impact Level: Application.";
tag_affected = "Novell eDirectory 8.8.5 before 8.8.5.6 (8.8.5.SP6)
  Novell eDirectory 8.8.6 before 8.8.6.2 (8.8.6.SP2) on Linux.";

tag_insight = "This flaw is caused by an error in the 'NCP' implementation when processing
  malformed 'FileSetLock' requests sent to port 524.";
tag_solution = "Upgrade to Novell eDirectory  8.8.5.6 or  8.8.6.2
  For updates refer to http://www.novell.com/products/edirectory/";
tag_summary = "This host is running Novell eDirectory is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(902291);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2010-4327");
  script_bugtraq_id(46263);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Novell eDirectory NCP Request Remote Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43186");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0305");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-060/");
  script_xref(name : "URL" , value : "http://www.novell.com/support/viewContent.do?externalId=7007781&amp;sliceId=2");

  script_description(desc);
  script_summary("Check for the version of Novell eDirectory");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("novell_edirectory_detect.nasl", "http_version.nasl",
                      "os_fingerprint.nasl");
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
include("host_details.inc");

# only eDirectory running under Linux is affected
if (host_runs("windows") == "yes") {
  exit(0);
}

## Get the default port
port = get_kb_item("Services/ldap");
if(!port){
  exit(0);
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get the version from KB
edirVer = get_kb_item(string("ldap/", port,"/eDirectory"));
if(isnull(edirVer)){
 exit(0);
}

edirVer = eregmatch(pattern:"(([0-9.]+).?([a-zA-Z0-9]+)?)", string:edirVer);
if(!isnull(edirVer[1]))
{
  ## Check for vulnerable versions
  edirVer = ereg_replace(pattern:"-| ", replace:".", string:edirVer[1]);
  if(version_in_range(version:edirVer, test_version:"8.8.5", test_version2:"8.8.5.SP5") ||
     version_in_range(version:edirVer, test_version:"8.8.6", test_version2:"8.8.6.SP1")) {
    security_warning(port);
  }
}
