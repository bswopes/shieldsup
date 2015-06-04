<?php
require('conf.php');
require('lib.php');

session_start();

// User is not logged in, redirect
if(empty($_SESSION['oauth_uid'])){
	header('Location: twitter_login.php');
	exit;
}

?>

<html>
<head>
<title>OAPI: Shields Up</title>

<style>
body {
	font-family: Arial, Helvetica, sans-serif;
	font-size: 1.2em;
}

table {
	margin: 0px;
	border: 0px;
	padding: 10px;
}
</style>
</head>

<body>

<?php
$sock = stream_socket_client("unix://$socket_file", $errno, $errstr);

// todo: make this error message prettier?

if ($errno) {
	print("something is wrong: <strong>$errstr!</strong><br />\n");
	print("the backend server probably isn't running. kick it.\n");
	print("</body></html>");
	exit;
}

// create a connection to our backend server
// serves no purpose beyond ensuring our auth works
$ret = login_to_backend(	$sock,
				$app_key,
				$app_secret,
				$_SESSION['oauth_token'],
				$_SESSION['oauth_token_secret'] );

// todo: put in a link to the webpage. we should add that to the conf file.
if ( $ret == "AUTH_ERR" ) {
	print("There seems to be a problem logging you in to twitter. ");
	print("Try hitting back in your browser to restart the process.\n");
	print("</body></html>");
	exit;
}

?>
<form action="step2.php" method="POST">

<table>
<tr>
<td>Twitter username:</td>
<td><input type="text" name="username"></td>
<td><input type="checkbox" name="retweet" value="Retweet" checked>Retweets<br>
<input type="checkbox" name="reply" value="Reply">Replies</td>
<td><input type="submit" value="Submit"></td>
</tr>
</table>

</form>

</body>
</html>

