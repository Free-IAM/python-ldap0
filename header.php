<?
	$pages = array(
		"index" =>	"Home",
		"lists" =>	"Lists",
		"release" =>	"Download",
		"docs" =>	"Docs"
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
	function srcrelease($name, $vers) {
		global $release_root;
		print "<tr><td><a href=\"$release_root/$name\">$vers</a></td>
			   </tr>\n";
	}

	#-- Binary package release
	function binrelease($name, $vers, $arch, $pyvers, $ldaplib, $note) {
		global $release_root;
		print "<tr><td><a href=\"$release_root/$name\">$vers</a></td>
			   <td>$arch</td>
			   <td>$pyvers</td>
			   <td>$ldaplib</td>
			   <td>$note &nbsp;</td>
			   </tr>\n";
	}

?>
