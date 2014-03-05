###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_135.nasl 9 2013-10-27 09:38:41Z jan $
#
# IT-Grundschutz, 11. EL, Ma�nahme 4.135
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
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
tag_summary = "IT-Grundschutz M4.135: Restriktive Vergabe von Zugriffsrechten auf Systemdateien.

  Diese Pr�fung bezieht sich auf die 11. Erg�nzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Ma�nahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Erg�nzungslieferung bezieht. Titel und Inhalt k�nnen sich bei einer
  Aktualisierung �ndern, allerdings nicht die Kernthematik.

  http://www.bsi.bund.de/grundschutz/kataloge/m/m04/m04135.html";

if(description)
{
  script_id(894135);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Tue Feb 02 16:39:34 2010 +0100");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.135: Restriktive Vergabe von Zugriffsrechten auf Systemdateien");
  
  if (! OPENVAS_VERSION)
  {
    desc = "Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!";
    script_description(desc);
    script_summary("IT-Grundschutz M4.135: Restriktive Vergabe von Zugriffsrechten auf Systemdateien.");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("IT-Grundschutz-11");
    exit(0);
  }
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("IT-Grundschutz M4.135: Restriktive Vergabe von Zugriffsrechten auf Systemdateien.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Tools/Present/wmi");
  script_mandatory_keys("Compliance/Launch/GSHB-11");
  script_dependencies("GSHB/GSHB_SSH_sys_dir_write_perm.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SMB_SDDL.nasl");
  script_require_keys("GSHB/ROOTSDDL");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

name = 'IT-Grundschutz M4.135: Restriktive Vergabe von Zugriffsrechten auf Systemdateien\n';



if (! OPENVAS_VERSION)
  {
        set_kb_item(name:"GSHB-10/M4_135/result", value:"nicht zutreffend");
        set_kb_item(name:"GSHB-10/M4_135/desc", value:"Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!");
        set_kb_item(name:"GSHB-10/M4_135/name", value:name);
    log_message(port:0, proto: "IT-Grundschutz", data:string("Leider setzen Sie einen zu alten OpenVAS Scan-Server ein. Bitte wechseln Sie auf die 3.0er-Serie des Scan-Servers!"));  
    exit(0);
}

include ("wmi_misc.inc");

gshbm =  "IT-Grundschutz M4.135: ";

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_NAME");
WindowsDomain = get_kb_item("WMI/WMI_WindowsDomain");
WindowsDomainrole = get_kb_item("WMI/WMI_WindowsDomainrole");
WINSDDL = get_kb_item("GSHB/WINSDDL");
ROOTSDDL = get_kb_item("GSHB/ROOTSDDL");
log = get_kb_item("WMI/WMI_OS/log");
log += '\n' + get_kb_item("GSHB/WINSDDL/log");
stat =  get_kb_item("GSHB/WINSDDL/stat");
Writeperm = get_kb_item("GSHB/Dir-Writeperm");
Writepermlog = get_kb_item("GSHB/Dir-Writeperm/log");

if(OSVER >!< "none" && stat){

  DEFINITION = "ace_type:ace_flags:rights:object_guid:inherit_object_guid:account_sid";
  VAL_ROOTSDDL = ereg_replace(pattern:"(\)\()", string:ROOTSDDL, replace:'|');
  VAL_ROOTSDDL = ereg_replace(pattern:"(\))", string:VAL_ROOTSDDL, replace:'|');
  VAL_ROOTSDDL = ereg_replace(pattern:"(\()", string:VAL_ROOTSDDL, replace:'|');

  SPL_ROOTSDDL= split(VAL_ROOTSDDL, sep:"|", keep:0);

  for(i=1; i<max_index(SPL_ROOTSDDL); i++){

    SPLROOTSDDL= split(SPL_ROOTSDDL[i], sep:";", keep:0);

    for(A = 0; A >= 0; A++)
    {
      if(ace_types[A] == NULL)
          break;

      if(ace_types[A] == SPLROOTSDDL[0])
        ACE = ace_types[A + 1];
    }
######################################
    ACEFLAG = NULL;
    for(B = 0; B >= 0; B++)
    {
      if(ace_flags[B] == NULL)
          break;

      aceflaglength = strlen(SPLROOTSDDL[1]); 
      if(ace_flags[B] >< SPLROOTSDDL[1] && aceflaglength == 2)
        ACEFLAG = ace_flags[B + 1];
      else if(ace_flags[B] >< SPLROOTSDDL[1] && aceflaglength > 2){
        if (!ACEFLAG) ACEFLAG = ace_flags[B + 1];
        else ACEFLAG += "/" + ace_flags[B + 1];
      }
    }
######################################
    ACM = NULL; 
    if (SPLROOTSDDL[2] =~ "0x(.*){8}")
    {
      for(C = 0; C >= 0; C++)
      {
        if(access_mask_hex[C] == NULL)
            break;

        ACMH_val = split(SPLROOTSDDL[2], sep:"x", keep:0);
        ACM_hex = toupper(ACMH_val[1]);
        ACM_hex = "0x" + ACM_hex;
        if(access_mask_hex[C] >< ACM_hex)
          ACM = access_mask_hex[C + 1];
        if (!ACM) ACM = ACM_hex;
      }  
    }else
   {
      for(C = 0; C >= 0; C++)
      {
        if(ace_access_mask[C] == NULL)
            break;
          
        acemasklength = strlen(SPLROOTSDDL[2]); 
        if(ace_access_mask[C] >< SPLROOTSDDL[2] && acemasklength == 2)
          ACM = ace_access_mask[C + 1];
        else if(ace_access_mask[C] >< SPLROOTSDDL[2] && acemasklength > 2){
          if (!ACM) ACM = ace_access_mask[C + 1];
          else ACM += "/" + ace_access_mask[C + 1];
        }
      }
    }  
##########################################
    for(D = 0; D >= 0; D++)
    {
      if(sid_codes[D] == NULL)
          break;

      if(sid_codes[D] == SPLROOTSDDL[5])
        SID = sid_codes[D + 1];
    }
  
  ROOTFULLACE +=  ACE + ":" + ACEFLAG +  ":" + ACM + ":::" + SID + '\n';
  }

#########################################################################

  VAL_WINSDDL = ereg_replace(pattern:"(\)\()", string:WINSDDL, replace:'|');
  VAL_WINSDDL = ereg_replace(pattern:"(\))", string:VAL_WINSDDL, replace:'|');
  VAL_WINSDDL = ereg_replace(pattern:"(\()", string:VAL_WINSDDL, replace:'|');

  SPL_WINSDDL= split(VAL_WINSDDL, sep:"|", keep:0);

  for(i=1; i<max_index(SPL_WINSDDL); i++){

    SPLWINSDDL= split(SPL_WINSDDL[i], sep:";", keep:0);

    for(A = 0; A >= 0; A++)
    {
      if(ace_types[A] == NULL)
          break;

      if(ace_types[A] == SPLWINSDDL[0])
        ACE = ace_types[A + 1];
    }
######################################
    ACEFLAG = NULL;
    for(B = 0; B >= 0; B++)
    {
      if(ace_flags[B] == NULL)
          break;

      aceflaglength = strlen(SPLWINSDDL[1]); 
      if(ace_flags[B] >< SPLWINSDDL[1] && aceflaglength == 2)
        ACEFLAG = ace_flags[B + 1] + ":";
      else if(ace_flags[B] >< SPLWINSDDL[1] && aceflaglength > 2){
        if (!ACEFLAG) ACEFLAG = ace_flags[B + 1];
        else ACEFLAG += "/" + ace_flags[B + 1];
      }
    }
######################################
    ACM = NULL;   
    if (SPLWINSDDL[2] =~ "0x(.*){8}")
    {
      for(C = 0; C >= 0; C++)
      {
        if(access_mask_hex[C] == NULL)
            break;

        ACMH_val = split(SPLWINSDDL[2], sep:"x", keep:0);
        ACM_hex = toupper(ACMH_val[1]);
        ACM_hex = "0x" + ACM_hex;
        if(access_mask_hex[C] >< ACM_hex)
          ACM = access_mask_hex[C + 1];
          if (!ACM) ACM = ACM_hex;
      }  
    }else
    {
      for(C = 0; C >= 0; C++)
      {
        if(ace_access_mask[C] == NULL)
            break;
          
        acemasklength = strlen(SPLWINSDDL[2]); 
        if(ace_access_mask[C] >< SPLWINSDDL[2] && acemasklength == 2)
          ACM = ace_access_mask[C + 1];
        else if(ace_access_mask[C] >< SPLWINSDDL[2] && acemasklength > 2){
          if (!ACM) ACM = ace_access_mask[C + 1];
          else ACM += "/" + ace_access_mask[C + 1];
        }
      }
    }  
##########################################
    for(D = 0; D >= 0; D++)
    {
      if(sid_codes[D] == NULL)
          break;

      if(sid_codes[D] == SPLWINSDDL[5])
        SID = sid_codes[D + 1];
    }

  WINFULLACE +=  ACE + ":" + ACEFLAG +  ":" + ACM + ":::" + SID + '\n';
  }

  if(OSVER >< "error" || WINSDDL >< "error"){
    result = string("Fehler");
    if (!log)desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log)desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }
  #Windows 2000 und kleiner:
  else if(OSVER <= '5.0')
  {
     result = string("unvollst�ndig");
     desc = string("Ungepr�ft");
  }

  #Windows XP und 2003:
  else if(OSVER > '5.0' && OSVER < '6.0' && OSTYPE != 2)
  {

    if (ROOTSDDL == "O:BAG:SYD:(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001f01ff;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;CI;LC;;;S-1-5-32-545)(A;CIIO;DC;;;S-1-5-32-545)(A;;0x001200a9;;;WD)" && WINSDDL == "O:BAG:SYD:PAI(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;;0x001301bf;;;S-1-5-32-547)(A;OICIIO;SDGRGWGX;;;S-1-5-32-547)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;CO)"){
  
      result = string("nicht erf�llt");
      desc = string('F�r das Systemlaufwerk und f�r das Windows-Verzeichnis\nsind die Default-Sicherheitseinstellungen hinterlegt.\nBitte �berpr�fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);

    }else if(ROOTSDDL != "O:BAG:SYD:(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001f01ff;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;CI;LC;;;S-1-5-32-545)(A;CIIO;DC;;;S-1-5-32-545)(A;;0x001200a9;;;WD)" && WINSDDL == "O:BAG:SYD:PAI(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;;0x001301bf;;;S-1-5-32-547)(A;OICIIO;SDGRGWGX;;;S-1-5-32-547)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;CO)"){

      result = string("unvollst�ndig");
      desc = string('F�r das Windows-Verzeichnis sind die Default-\nSicherheitseinstellungen hinterlegt. Die Sicherheits-\neinstellungen f�r das Systemlaufwerk wurden ge�ndert.\nBitte �berpr�fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);

    }else if(ROOTSDDL == "O:BAG:SYD:(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001f01ff;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;CI;LC;;;S-1-5-32-545)(A;CIIO;DC;;;S-1-5-32-545)(A;;0x001200a9;;;WD)" && WINSDDL != "O:BAG:SYD:PAI(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;;0x001301bf;;;S-1-5-32-547)(A;OICIIO;SDGRGWGX;;;S-1-5-32-547)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;CO)"){

      result = string("unvollst�ndig");
      desc = string('F�r das Systemlaufwerk sind die Default-Sicherheits-\neinstellungen hinterlegt. Die Sicherheitseinstellungen\nf�r das Windows-Verzeichnis wurden ge�ndert. Bitte\n�berpr�fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else{

      result = string("unvollst�ndig");
      desc = string('F�r das Systemlaufwerk und Windows-Verzeichnis wurden\ndie Sicherheitseinstellungen ge�ndert. Sie entsprechen\nnicht mehr den Default-Einstellungen. Bitte �berpr�fen\nSie die Sicherheitseinstellungen und passen sie diese\nggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }
  }

  #Windows 2003 Domaincontroller:
  else if(OSVER == '5.2' && OSTYPE == 2 )
  {
    if (ROOTSDDL == "O:BAG:SYD:(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001f01ff;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;CI;LC;;;S-1-5-32-545)(A;CIIO;DC;;;S-1-5-32-545)(A;;0x001200a9;;;WD)" && WINSDDL == "O:BAG:SYD:PAI(A;;0x001200a9;;;AU)(A;OICIIO;GRGX;;;AU)(A;;0x001301bf;;;S-1-5-32-549)(A;OICIIO;SDGRGWGX;;;S-1-5-32-549)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;CO)"){
  
      result = string("nicht erf�llt");
      desc = string('F�r das Systemlaufwerk und f�r das Windows-Verzeichnis\nsind die Default-Sicherheitseinstellungen hinterlegt.\nBitte �berpr�fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);

    }else if(ROOTSDDL != "O:BAG:SYD:(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001f01ff;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;CI;LC;;;S-1-5-32-545)(A;CIIO;DC;;;S-1-5-32-545)(A;;0x001200a9;;;WD)" && WINSDDL == "O:BAG:SYD:PAI(A;;0x001200a9;;;AU)(A;OICIIO;GRGX;;;AU)(A;;0x001301bf;;;S-1-5-32-549)(A;OICIIO;SDGRGWGX;;;S-1-5-32-549)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;CO)"){

      result = string("unvollst�ndig");
      desc = string('F�r das Windows-Verzeichnis sind die Default-\nSicherheitseinstellungen hinterlegt. Die Sicherheits-\neinstellungen f�r das Systemlaufwerk wurden ge�ndert.\nBitte �berpr�fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);

    }else if(ROOTSDDL == "O:BAG:SYD:(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001f01ff;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;CI;LC;;;S-1-5-32-545)(A;CIIO;DC;;;S-1-5-32-545)(A;;0x001200a9;;;WD)" && WINSDDL != "O:BAG:SYD:PAI(A;;0x001200a9;;;AU)(A;OICIIO;GRGX;;;AU)(A;;0x001301bf;;;S-1-5-32-549)(A;OICIIO;SDGRGWGX;;;S-1-5-32-549)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;CO)"){

      result = string("unvollst�ndig");
      desc = string('F�r das Systemlaufwerk sind die Default-Sicherheits-\neinstellungen hinterlegt. Die Sicherheitseinstellungen\nf�r das Windows-Verzeichnis wurden ge�ndert. Bitte\n�berpr�fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else{
      result = string("unvollst�ndig");
      desc = string('F�r das Systemlaufwerk und Windows-Verzeichnis wurden\ndie Sicherheitseinstellungen ge�ndert. Sie entsprechen\nnicht mehr den Default-Einstellungen. Bitte �berpr�fen\nSie die Sicherheitseinstellungen und passen sie diese\nggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }
  }


  #Vista und Windows 7
  else if(OSVER >= '6.0' && OSTYPE == 1)
  {
    if (ROOTSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;OICIIO;SDGRGWGX;;;AU)(A;;LC;;;AU)" && WINSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){
  
      result = string("nicht erf�llt");
      desc = string('F�r das Systemlaufwerk und f�r das Windows-Verzeichnis\nsind die Default-Sicherheitseinstellungen hinterlegt.\nBitte �berpr�fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);

    }else if(ROOTSDDL != "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;OICIIO;SDGRGWGX;;;AU)(A;;LC;;;AU)" && WINSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){

      result = string("unvollst�ndig");
      desc = string('F�r das Windows-Verzeichnis sind die Default-\nSicherheitseinstellungen hinterlegt. Die Sicherheits-\neinstellungen f�r das Systemlaufwerk wurden ge�ndert.\nBitte �berpr�fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);

    }else if(ROOTSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;OICIIO;SDGRGWGX;;;AU)(A;;LC;;;AU)" && WINSDDL != "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){

      result = string("nicht erf�llt");
      desc = string('F�r das Systemlaufwerk sind die Default-Sicherheits-\neinstellungen hinterlegt. Die Sicherheitseinstellungen\nf�r das Windows-Verzeichnis wurden ge�ndert. Bitte\n�berpr�fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else{
      result = string("nicht erf�llt");
      desc = string('F�r das Systemlaufwerk und Windows-Verzeichnis wurden\ndie Sicherheitseinstellungen ge�ndert. Bitte\n�berpr�fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }
  }

  #Windows 2008 und 2008 R2 NON Domaincontroller
  else if(OSVER >= '6.0' && OSTYPE == 3)
  {

    if (ROOTSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;OICIIO;SDGRGWGX;;;AU)(A;;LC;;;AU)" && WINSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){
  
      result = string("nicht erf�llt");
      desc = string('F�r das Systemlaufwerk und f�r das Windows-Verzeichnis\nsind die Default-Sicherheitseinstellungen hinterlegt.\nBitte �berpr�fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    
    }else if(ROOTSDDL != "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;OICIIO;SDGRGWGX;;;AU)(A;;LC;;;AU)" && WINSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){

      result = string("unvollst�ndig");
      desc = string('F�r das Windows-Verzeichnis sind die Default-\nSicherheitseinstellungen hinterlegt. Die Sicherheits-\neinstellungen f�r das Systemlaufwerk wurden ge�ndert.\nBitte �berpr�fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);

    }else if(ROOTSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001f01ff;;;SY)(A;OICIIO;GA;;;SY)(A;OICI;0x001200a9;;;S-1-5-32-545)(A;OICIIO;SDGRGWGX;;;AU)(A;;LC;;;AU)" && WINSDDL != "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){

      result = string("nicht erf�llt");
      desc = string('F�r das Systemlaufwerk sind die Default-Sicherheits-\neinstellungen hinterlegt. Die Sicherheitseinstellungen\nf�r das Windows-Verzeichnis wurden ge�ndert. Bitte\n�berpr�fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else{
      result = string("nicht erf�llt");
      desc = string('F�r das Systemlaufwerk und Windows-Verzeichnis wurden\ndie Sicherheitseinstellungen ge�ndert. Bitte\n�berpr�fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }
  }

  #Windows 2008 und 2008 R2 Domaincontroller
  else if(OSVER >= '6.0' && OSTYPE == 2)
  {

    if (ROOTSDDL == "O:BAG:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;0x001f01ff;;;CO)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001f01ff;;;BA)(A;CIIO;0x00100002;;;S-1-5-32-545)(A;CI;0x00100004;;;S-1-5-32-545)(A;OICI;0x001200a9;;;S-1-5-32-545)" && WINSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){
  
      result = string("nicht erf�llt");
      desc = string('F�r das Systemlaufwerk und f�r das Windows-Verzeichnis\nsind die Default-Sicherheitseinstellungen hinterlegt.\nBitte �berpr�fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    
    }else if(ROOTSDDL != "O:BAG:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;0x001f01ff;;;CO)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001f01ff;;;BA)(A;CIIO;0x00100002;;;S-1-5-32-545)(A;CI;0x00100004;;;S-1-5-32-545)(A;OICI;0x001200a9;;;S-1-5-32-545)" && WINSDDL == "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){

      result = string("unvollst�ndig");
      desc = string('F�r das Windows-Verzeichnis sind die Default-\nSicherheitseinstellungen hinterlegt. Die Sicherheits-\neinstellungen f�r das Systemlaufwerk wurden ge�ndert.\nBitte �berpr�fen Sie die Sicherheitseinstellungen und\npassen sie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);

    }else if(ROOTSDDL == "O:BAG:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;0x001f01ff;;;CO)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001f01ff;;;BA)(A;CIIO;0x00100002;;;S-1-5-32-545)(A;CI;0x00100004;;;S-1-5-32-545)(A;OICI;0x001200a9;;;S-1-5-32-545)" && WINSDDL != "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x001f01ff;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x001301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x001301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x001200a9;;;S-1-5-32-545)(A;OICIIO;GRGX;;;S-1-5-32-545)(A;OICIIO;GA;;;CO)"){

      result = string("nicht erf�llt");
      desc = string('F�r das Systemlaufwerk sind die Default-Sicherheits-\neinstellungen hinterlegt. Die Sicherheitseinstellungen\nf�r das Windows-Verzeichnis wurden ge�ndert. Bitte\n�berpr�fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }else{
      result = string("nicht erf�llt");
      desc = string('F�r das Systemlaufwerk und Windows-Verzeichnis wurden\ndie Sicherheitseinstellungen ge�ndert. Bitte\n�berpr�fen Sie die Sicherheitseinstellungen und passen\nsie diese ggf. an.' + '\nRechte Systemlaufwerk:\n' + DEFINITION + '\n' + ROOTFULLACE + '\nRechte Windows-Verzeichnis:\n' + DEFINITION + '\n' + WINFULLACE);
    }
  }
}else{

  if(!stat){
    result = string("Fehler");
    desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine File and Folder ACL abgerufen werden.");
  }else if(Writeperm >< "error"){
    result = string("Fehler");
    if (!Writepermlog)desc = string('Beim Testen des Systems trat ein\nunbekannter Fehler auf.');
    if (Writepermlog)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
  }else if(Writeperm >< "none"){
    result = string("erf�llt");
    desc = string('Es wurden, ausgenommen von /home/* und /tmp/*, keine\nVerzeichnisse mit Schreibrecht f�r Benutzer gefunden.');
  }else if(Writeperm == "windows") {
    result = string("Fehler");
    if (OSNAME >!< "none" && OSNAME >!< "error") desc = string('Folgendes System wurde erkannt:\n' + OSNAME + '\nAllerdings konnten die Sicherheitseinstellungen der\nVerzeichnisse nicht gelesen werden. Folgende Fehler\nsind aufgetreten:\n' + log);
    else desc = string('Das System scheint ein Windows-System zu sein.\nAllerdings konnten die Sicherheitseinstellungen der\nVerzeichnisse nicht gelesen werden. Folgende Fehler\nsind aufgetreten:\n' + log);
  }else if(Writeperm >< "nofind") {
    result = string("Fehler");
    desc = string('Beim Testen des Systems wurde der Befehl -find-\nnicht gefunden.');
  }else{
    result = string("nicht erf�llt");
    desc = string('Es wurden, ausgenommen von /home/* und /tmp/*,\nfolgende Verzeichnisse mit Schreibrecht f�r Benutzer\ngefunden:\n' + Writeperm);
  }

}

if (!result){
      result = string("Fehler");
      desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.'); 
}

set_kb_item(name:"GSHB-11/M4_135/result", value:result);
set_kb_item(name:"GSHB-11/M4_135/desc", value:desc);
set_kb_item(name:"GSHB-11/M4_135/name", value:name);

silence = get_kb_item("GSHB-11/silence");

if (silence){
exit(0);
} else {
  report = 'Ergebnisse zum IT-Grundschutz, 11. Erg�nzungslieferung:\n\n';
  report = report + name + 'Ergebnis:\t' + result +
           '\nDetails:\t' + desc + '\n\n';
    if ("nicht erf�llt" >< result || result >< "Fehler"){
    security_hole(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "unvollst�ndig"){
    security_warning(port:0, proto: "IT-Grundschutz", data:report);
    } else if (result >< "erf�llt" || result >< "nicht zutreffend"){
    security_note(port:0, proto: "IT-Grundschutz", data:report);
    }
exit(0);
}

