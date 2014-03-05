###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap6_x11_access.nasl 10 2013-10-27 10:03:59Z jan $
#
# Autogenerated NSE wrapper
#
# Authors:
# NSE-Script: vladz
# NASL-Wrapper: autogenerated
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Checks if you're allowed to connect to the X server.

If the X server is listening on TCP port 6000+n (where n is the display number), it is possible to
check if you're able to get connected to the remote display by sending a X11 initial connection
request.

In reply, the success byte (0x00 or 0x01) will determine if you are in the 'xhost +'
list. In this case, script will display the message: 'X server access is granted'.";

if(description)
{
    script_id(803528);
    script_version("$Revision: 10 $");
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
    script_tag(name:"risk_factor", value:"None");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:03:59 +0100 (So, 27. Okt 2013) $");
    script_tag(name:"creation_date", value:"2013-02-28 19:00:17 +0530 (Thu, 28 Feb 2013)");
    script_name("Nmap NSE 6.01: x11-access");
    desc = "
    Summary:
    " + tag_summary;

    script_description(desc);

    script_summary("Nmap NSE 6.01: x11-access");
    script_category(ACT_ATTACK);
    script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
    script_family("Nmap NSE");



    script_dependencies("toolcheck.nasl");
    script_mandatory_keys("Tools/Present/nmap6.01");
    script_mandatory_keys("Tools/Launch/nmap_nse");

    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}



# Get the preferences
i = 0;


argv = make_list("nmap", "--script=x11-access.nse", get_host_ip());

if(i > 0)
{
  scriptArgs= "--script-args=";
  foreach arg(args) {
    scriptArgs += arg + ",";
  }
  argv = make_list(argv,scriptArgs);
}

## Run nmap and Get the Result
res = pread(cmd: "nmap", argv: argv);

if(res)
{
  foreach line (split(res))
  {
    if(port = eregmatch(pattern:"^([0-9]+)/tcp",string:line))
    {
      port = port[1];
      result = NULL;
      continue;
    }
    if(ereg(pattern:"^\|",string:line)) {
      result +=  substr(chomp(line),2) + '\n';
    }

    error = eregmatch(string:line, pattern:"^nmap: (.*)$");
    if (error) {
      msg = string('Nmap command failed with following error message:\n', line);
      log_message(data : msg, port:port);
    }
  }

  if("x11-access" >< result) {
    msg = string('Result found by Nmap Security Scanner (x11-access.nse) ',
                'http://nmap.org:\n\n', result);
    log_message(data : msg, port:port);
  }
}
else
{
  msg = string('Nmap command failed entirely:\n', 'nmap ', argv);
  log_message(data: msg, port:port);
}