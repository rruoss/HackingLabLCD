###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_rational_deve_for_system_z_info_disc_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# IBM Rational Developer for System z Information Disclosure Vulnerability (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow local users to obtain sensitive information
  via unspecified vectors.
  Impact Level: Application";
tag_affected = "IBM Rational Developer for System z version 7.1 through 8.5.1 on Windows";
tag_insight = "The flaw is due to error in the application, which does not properly store the
  SSL certificate password.";
tag_solution = "Upgrade to IBM Rational Developer for System z version 8.5.2 or later,
  For updates refer to http://www.ibm.com/developerworks/downloads/r/rdz/index.html";
tag_summary = "This host is installed with IBM Rational Developer for System z and
  is prone information disclosure vulnerability.";

if(description)
{
  script_id(802687);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4862");
  script_bugtraq_id(56725);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-21 19:17:26 +0530 (Wed, 19 Dec 2012)");
  script_name("IBM Rational Developer for System z Information Disclosure Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/87925");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51401/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/79919");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21617886");

  script_description(desc);
  script_summary("Check for the version of IBM Rational Developer for System z on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialisation
share = "";
rdzVer = "";
rdzFile = "";
rdzPath = "";
filePath = "";
swFile = "IBM_Rational_Developer_for_zEnterprise";
ibmKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" +
         "\\RDzEnt-IBM Software Delivery Platform";
## list of software package versions
swPkgVers = make_list("7.1", "7.5", "7.5.1", "7.5.1.3", "7.5.1.4", "7.6",
                      "7.6.1", "7.6.2", "7.6.2.2", "7.6.2.3", "7.6.2.4",
                      "8.0.1", "8.0.2", "8.0.3", "8.0.3.1", "8.0.3.2",
                      "8.0.3.3", "8.5", "8.5.0", "8.5.0.1", "8.5.1");

## check key existance
if(!registry_key_exists(key:ibmKey)) exit(0);

## get key from registry
rdzPath = registry_get_sz(key:ibmKey, item:"DisplayIcon");

## confirm product installation
if(!rdzPath) exit(0);

## check the path
if(rdzPath && rdzPath =~ "\\SDP\\rdz")
{
  foreach ext (make_list(".", "-"))
  {
    foreach swPkgVer (swPkgVers)
    {
      ## build file path and get the file content
      swFilePath = rdzPath - "RDz.ico" + "properties\\version\\" +
                   swFile + ext + swPkgVer + ".swtag";
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:swFilePath);
      filePath = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",string:swFilePath);
      rdzFile = read_file(share:share, file:filePath, offset:0, count:250);

      ## check the product name and file version
      if(rdzFile && rdzFile =~ "ProductVersion>[0-9\.]+<" &&
         rdzFile =~ "ProductName>IBM Rational Developer for zEnterprise")
      {
        rdzVer = eregmatch(pattern:"ProductVersion>([0-9\.]+)<", string:rdzFile);

        if(version_in_range(version:rdzVer[1], test_version:"7.1",test_version2:"8.5.1"))
        {
          security_warning(0);
          exit(0);
        }
      }
    }
  }
}
