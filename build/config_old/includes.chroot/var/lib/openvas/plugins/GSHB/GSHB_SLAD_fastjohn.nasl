###############################################################################
# OpenVAS Vulnerability Test
#
# Fetch results of SLAD queries from a remote machine
#
# Primary Authors:
# Dirk Jagdmann
# Michael Wiegand
#
# Changed for GSHB by:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 DN-Systems GmbH
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
################################################################################

include("revisions-lib.inc");
tag_summary = "This script connects to SLAD on a remote host to run
remote john password scanner in fastmode.
To work properly, this script requires to be provided
with a valid SSH login by means of an SSH key with pass-
phrase if the SSH public key is passphrase-protected, or
a password to log in.";

include ("ssh_func.inc");
include ("slad.inc");

if (description) {
  script_id(96061);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Thu Feb 25 12:13:41 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");  
  name = "SLAD fastjohn Run";
  script_name(name);
  
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  
  summary = "Connects to SLAD to run programs remotely";
  script_summary(summary);
  
  script_category(ACT_GATHER_INFO);
  
  script_copyright("This script is Copyright 2010 DN Systems GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("find_service.nasl", "ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

function run_slad_fastjohn (sock, slad_exe) {
  global_var johnresult;
  slad_cmd = slad_exe + " -r john:fastjohn";
  results = ssh_cmd (socket: sock, cmd: slad_cmd, timeout: 120);
  if (results)  johnresult = results; 
  else set_kb_item(name:"GSHB/SLAD/FASTJOHN", value:"no results");
  if (results =~ ".*/opt/slad/bin/sladd: No such file or directory.*" || results =~ ".*/opt/slad/bin/sladd: Datei oder Verzeichnis nicht gefunden.*") {
    set_kb_item(name:"GSHB/SLAD/FASTJOHN", value:"noslad");  
    close (sock);
    exit(0);
  }
}

sock = ssh_login_or_reuse_connection();
if(!sock) {
  error = get_ssh_error();
  if (!error) error = "No SSH Port or Connection!";
  set_kb_item(name:"GSHB/SLAD/FASTJOHN", value:"no ssh");
  set_kb_item(name:"GSHB/SLAD/FASTJOHN/log", value:error);
  exit(0);
}

run_slad_fastjohn (sock: sock, slad_exe: "/opt/slad/bin/sladd");
  
if ("403 plugin already running" >< johnresult || "200 queued" >< johnresult)
{

  slad_exe = '/opt/slad/bin/sladd';
  slad_cmd = slad_exe + ' -s jobs';

  report = ssh_cmd (socket:sock, cmd:slad_cmd, timeout:60);

  bhead = report;
  while (bhead) {
    eol = strstr (bhead, string ("\n"));
    line = substr (bhead, 0, strlen (bhead) - strlen (eol) -1);
    bhead = substr (bhead, strlen (line) + 1);
    parts = split (line, sep: ':', keep: FALSE);
    job = parts[1] + ":" + parts[2] + ":" + parts[3];
    desc = get_slad_description (entry: job);

    if (parts[0] == "R" && parts[1] == "john" && parts[2] == "fastjohn" && parts[3] == "fastjohn") {
      running += string (desc + "\n");
    } else if (parts[0] == "T" && parts[1] == "john" && parts[2] == "fastjohn" && parts[3] == "fastjohn") {
      results += string (desc + "\n");
      slad_cmd = slad_exe + ' -s ' + job;
      results += ssh_cmd (socket:sock, cmd:slad_cmd, timeout:60);
      results += string ("\n");
    }
  }
  if (results) {
    if ("guesses:" >< results){
       Lst = split(results, keep:0);
       for(i=1; i<max_index(Lst); i++){
         if ("guesses:" >< Lst[i]) continue;
         if (" passwords with " >< Lst[i]) continue;
         if (Lst[i] == "") continue;
         tmp = Lst[i] - "(WEAK)";
         tmp = ereg_replace(string:tmp, pattern:" ", replace:"");
         weakpwuser += tmp + ", ";
       }
       set_kb_item(name:"GSHB/SLAD/FASTJOHN", value:"NOPW=" + nopwuser + "|WEAK=" + weakpwuser);
    }
    else{
      Lst = split(results, keep:0);
      for(i=1; i<max_index(Lst); i++){
    
        if (Lst[i] == "" || "password hashes cracked" >< Lst[i] || "john:fastjohn:fastjohn" >< Lst[i]) continue;
           user = split(Lst[i], sep:":", keep:0);
           if ("NO PASSWORD***" ><user[3]) nopwuser += user[0] + ", ";
           else if (user[3]) weakpwuser += user[0] + ", ";
      }
    
    set_kb_item(name:"GSHB/SLAD/FASTJOHN", value:"NOPW=" + nopwuser + "|WEAK=" + weakpwuser);
    }
  }
  
  if (running) set_kb_item(name:"GSHB/SLAD/FASTJOHN", value: string ("Still running processes: \n" + running));
}
if (!results) set_kb_item(name:"GSHB/SLAD/FASTJOHN", value:"none");
close (sock);
exit(0);
