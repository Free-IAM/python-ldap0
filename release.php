<!-- $Id: release.php,v 1.2 2000/08/13 22:46:25 leonard Exp $ -->
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
	<table>
	<? release("src-dummy1", "dummy", "dummy") ?>
	<? release("src-dummy2", "dummy", "dummy") ?>
	</table>
    </td>
    <td>
	<table>
	<? release("src-dummy1", "dummy", "dummy") ?>
	<? release("src-dummy2", "dummy", "dummy") ?>
	</table>
    </td>
</tr>
</table>

<dl>
<dt>CVS
<dd>Access the source repository at
<i>cvs.python-ldap.sourceforge.net:/cvsroot/python-ldap</i>

<dt>Historic
<dd>Some historic release for <i>ldapmodule</i> may be available from
    <a href="http://www.csee.uq.edu.au/~leonard/dc-prj/ldapmodule/">David Leonard's ldapmodule page</a>.
</dl>

<hr>
<i>$Id: release.php,v 1.2 2000/08/13 22:46:25 leonard Exp $</i>
</BODY>
</HTML>
