###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_rails_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Ruby On Rails Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_summary = "This script detect the installed version of Ruby On Rails
  and sets the result in KB.";

if(description)
{
  script_id(800911);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Ruby On Rails Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Ruby On Rails");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("version_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800911";
SCRIPT_DESC = "Ruby On Rails Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

rorPaths = find_file(file_name:"rails", file_path:"/", useregex:TRUE,
                       regexpar:"$", sock:sock);
foreach rorBin (rorPaths)
{
  rorVer = get_bin_version(full_prog_name:chomp(rorBin), sock:sock,
                             version_argv:"-v",
                             ver_pattern:"Rails ([0-9.]+)");
  if(rorVer[1] != NULL)
  {
    set_kb_item(name:"Ruby-Rails/Linux/Ver", value:rorVer[1]);
    security_note(data:"Ruby On Rails version " + rorVer[1] + 
                 " running at location " + rorBin + " was detected on the host");

    ## build cpe and store it as host_detail
    cpe = build_cpe(value: rorVer[1], exp:"^([0-9.]+)",base:"cpe:/a:ruby_on_rails:ruby_on_rails:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
ssh_close_connection();
