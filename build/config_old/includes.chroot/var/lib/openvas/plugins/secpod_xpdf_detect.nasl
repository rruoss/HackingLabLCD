###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xpdf_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Xpdf Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-22
# Revised to comply with Change Request #57.
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

tag_vuldetect = "The script logs in via ssh, searches for executable 'xpdf' and
  queries the found executables via command line option '-v'.";

tag_summary = "The PDF viewer Xpdf is installed and its version is detected.";

tag_solution = "N/A";

tag_affected = "Xpdf on Linux.";

tag_insight = "N/A";

tag_impact = "N/A";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900466";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-06 08:04:28 +0200 (Wed, 06 May 2009)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"detection", value:"executable version check");
  script_name("Xpdf Version Detection");

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "impact" , value : tag_impact);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "detection" , value : tag_vuldetect);
  }
  }

  script_description(desc);
  script_summary("Detection of installed version of Xpdf");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  if (defined_func("error_message"))
    error_message(port:port, data:"Failed to open ssh port.");
  exit(-1);
}

xpdfPaths = find_file(file_name:"xpdf", file_path:"/", useregex:TRUE,
                       regexpar:"$", sock:sock);
foreach executableFile (xpdfPaths)
{
  executableFile = chomp(executableFile);
  xpdfVer = get_bin_version(full_prog_name:executableFile, sock:sock,
                            version_argv:"-v",
                            ver_pattern:"xpdf version ([0-9]\.[0-9]+([a-z]?))");
  if(xpdfVer[1] != NULL)
  {
    set_kb_item(name:"Xpdf/Linux/Ver", value:xpdfVer[1]);
   
    cpe = build_cpe(value:xpdfVer[1], exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:foolabs:xpdf:");
    if(!isnull(cpe))
      register_product(cpe:cpe, location:executableFile, nvt:SCRIPT_OID);

    log_message(data:'Detected Xpdf version: ' + xpdfVer[1] +
        '\nLocation: ' + executableFile +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' + xpdfVer[max_index(xpdfVer)-1]);
  }
}

ssh_close_connection();
