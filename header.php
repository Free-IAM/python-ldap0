<?
	$pages = array(
		"index" =>	"Home",
		"lists" =>	"Lists",
		"release" =>	"Download"
	);

	function menubar() {
		global $thishref, $pages;
		$delim = "<p align=right>[";
		reset ($pages);
		while (list($href,$title) = each($pages)) {
			print $delim;
			if ($href != $thishref) {
				print "<a href=\"" . $href . ".php\">" .
					$title . "</a>";
			} else {
				print $title;
			}
			$delim = "|";
		}
		if ($delim == "|") {
			print "]</p>";
		}
	}

	$release_root = "ftp://python-ldap.sourceforge.net/pub/python-ldap";

	#-- Source code release
	function srcrelease($name) {
		print "<tr><td><a href=\"$release_root/$name\">$name</a></td>
			   </tr>\n";
	}

	#-- Binary package release
	function binrelease($name, $arch, $pyvers $ldaplib, $note) {
		print "<tr><td><a href=\"$release_root/$name\">$name</a></td>
			   <td>$arch</td>
			   <td>$pyvers</td>
			   <td>$ldaplib</td>
			   <td>$note &nbsp;</td>
			   </tr>\n";
	}

?>
