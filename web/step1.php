<?php
	require('conf.php');
	require('lib.php');

	$sock = su_session_start($socket_file, $app_key, $app_secret);

	print_html_header();

	?>
<form action="step2.php" method="POST">

<table>
<tr>
<td>Twitter username (source of unwanted attention):</td>
<td><input type="text" name="username"></td>
<td><input type="submit" value="Submit"></td>
</tr>
</table>

</form>

</body>
</html>