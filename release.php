<!-- $Id: release.php,v 1.3 2000/08/14 02:59:40 leonard Exp $ -->
<?
	$thishref = "release";
	include("header.php");
?>
<HTML><HEAD>
	<TITLE>Python-LDAP: Download</TITLE>
</HEAD>
<BODY>

<? menubar() ?>

<h1>Python-LDAP: Download</h1>

<table border=0>
<tr><th> Source </th>
    <th> Binary </th>
</tr><tr valign=top>
    <td>
	<table border=1>
	<? srcrelease("ldap-1.10alpha-src.tar.gz") ?>
	</table>
    </td>
    <td>
	<table border=1>
	<tr><th>&nbsp;</th>
	    <th>OS</th>
	    <th>Python</th>
	    <th>LDAP</th>
	</tr>
	<!--	   filename, OS, Python, LDAP -->
	<? if (0) binrelease("ldap-1.10alpha-linux-x86.rpm", 
		      "Linux 2.2.14-5.0.14smp",
		      "1.5.2"
		      "OpenLDAP 1.2.11") ?>
	<? binrelease("ldap-1.10alpha-OpenBSD-i386.tgz", 
		      "OpenBSD/i386 2.7",
		      "1.6a2"
		      "OpenLDAP 1.2.11") ?>
	</table>
    </td>
</tr>
</table>

<dl>
<dt>CVS
<dd>The CVS source repository can be accessed using pserver or ssh protocols at
<i>cvs.python-ldap.sourceforge.net:/cvsroot/python-ldap</i>
(username <tt>anonymous</tt>, password <tt>anonymous</tt>.)

<dt>Historic
<dd>Some historic release for <i>ldapmodule</i> may be available from
    <a href="http://www.csee.uq.edu.au/~leonard/dc-prj/ldapmodule/">David Leonard's ldapmodule page</a>.
</dl>

<hr>
<i>$Id: release.php,v 1.3 2000/08/14 02:59:40 leonard Exp $</i>
</BODY>
</HTML>
