# OpenVAS
# $Id: ssh_authorization.nasl 41 2013-11-04 19:00:12Z jan $
# Description: This script allows to set SSH credentials for target hosts.
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
# Felix Wolfsteller <felix.wolfsteller@greenbone.net>
# Chandrashekhar B <bchandra@secpod.com>
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2007,2008,2009,2010,2011,2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the
# Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

include("revisions-lib.inc");
tag_summary = "This script tries to login with provided credentials.

If the login was successful, it marks this port as available
for any authenticated tests.";

if(description)
{
 script_id(90022);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2007-11-01 23:55:52 +0100 (Thu, 01 Nov 2007)");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("SSH Authorization Check");

 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary("Try to login with provided credentials");
 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright 2007-2012 Greenbone Networks GmbH");
 script_family("General");
 script_dependencies("find_service.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("ssh_func.inc");

# Check if port for us is known
port = get_preference("auth_port_ssh");

if(!port) {
    port = get_kb_item("Services/ssh");
}
if(!port)
{
  log_message(data:'No port for an ssh connect was found open.\nHence authenticated checks are not enabled.');
  exit(0); # If port is not open
}

# Check if an account was defined either by the preferences ("old") or by the
# server ("new").

if(kb_ssh_login() && (kb_ssh_password() || kb_ssh_publickey()))
{

  sock = ssh_login_or_reuse_connection();

  if(!sock)
  {
    log_message(data: 'It was not possible to login using the provided SSH credentials.\nHence authenticated checks are not enabled.', port:port);
    ssh_close_connection();
    exit(0);
  }

  set_kb_item(name:"login/SSH/success", value:TRUE);

  ## Confirm Linux and set the KB
  result = ssh_cmd(socket:sock, cmd:"uname");
  if("Linux" >< result){
    set_kb_item(name:"login/SSH/Linux", value:TRUE);
  }


  log_message(data:'It was possible to login using the provided SSH credentials.\nHence authenticated checks are enabled.', port:port);
  ssh_close_connection();
}
else
{
  # Actually it is not necessary to send log information in case no
  # credentials at all were provided. The user simply does not want
  # to run a authenticated scan.
  #log_message(data:'No sufficient SSH credentials were supplied.\nHence authenticated checks are not enabled.', port:port);
}

exit(0);
