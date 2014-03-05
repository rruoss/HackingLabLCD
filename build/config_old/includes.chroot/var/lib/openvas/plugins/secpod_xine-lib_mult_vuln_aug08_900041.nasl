##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xine-lib_mult_vuln_aug08_900041.nasl 16 2013-10-27 13:09:52Z jan $
# Description: xine-lib Multiple Vulnerabilities (Aug-08)
#
# Authors:
# Chandan S <schandan@secpod.com>
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
tag_impact = "Remote exploitation could allow execution of arbitrary code
        to cause head-based buffer overflow via a specially crafted RealAudio
        or Matroska file.
 Impact Level : Application/System";

tag_solution = "No solution or patch is available as of 26th August, 2008. Information
 regarding this issue will updated once the solution details are available.
 For updates refer to http://xinehq.de/index.php/releases";

tag_affected = "xine-lib versions 1.1.15 and prior on Linux (All).";

tag_insight = "The flaws are due to overflow errors that exist in open_ra_file()
        in demux_realaudio.c, parse_block_group() in demux_matroska.c,
        and eal_parse_audio_specific_data() in demux_real.c methods.";


tag_summary = "The host has xine-lib installed, which prone to multiple
 vulnerabilities.";


if(description)
{
 script_id(900041);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-27 11:53:45 +0200 (Wed, 27 Aug 2008)");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_category(ACT_GATHER_INFO);
 script_family("Buffer overflow");
 script_name("xine-lib Multiple Vulnerabilities (Aug-08)");
 script_summary("Check for vulnerable version of xine-lib");
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
 script_dependencies("gather-package-list.nasl");
 script_require_keys("ssh/login/uname");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31567/");
 script_xref(name : "URL" , value : "http://www.ocert.org/analysis/2008-008/analysis.txt");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 exit(0);
}


 include("ssh_func.inc");

 if("Linux" >!< get_kb_item("ssh/login/uname")){
        exit(0);
 }
 
 foreach item (get_kb_list("ssh/*/rpms"))
 {
        if("xine" >< item)
        {
                if(egrep(pattern:"(libxine(1)?|xine-lib)~(0\..*|1\.(0\..*|" +
				 "1(\.0?[0-9]|\.1[0-5])?))[^.0-9]", string:item))
		{
                        security_warning(0);
			exit(0);
		}
	}
 }

 sock = ssh_login_or_reuse_connection();
 if(!sock){
 	exit(0);
 }

 xineVer = ssh_cmd(socket:sock, cmd:"xine-config --version", timeout:timeout);
 ssh_close_connection();

 if(!xineVer){
 	exit(0);
 }

 if(egrep(pattern:"^(0\..*|1\.(0\..*|1(\.0?[0-9]|\.1[0-5])?))([^.0-9]|$)",
	  string:xineVer)){
 	security_warning(0);
 } 
