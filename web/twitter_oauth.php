<?php

    include("conf.php");
    require("twitteroauth/twitteroauth.php");

    session_start();
    $mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
    if ($mysqli->connect_errno) {
        echo "Failed to connect to MySQL: (" . $mysqli->connect_errno . ") " . $mysqli->connect_error;
    }

if(!empty($_GET['oauth_verifier']) && !empty($_SESSION['oauth_token']) && !empty($_SESSION['oauth_token_secret'])){

    // We've got everything we need
	// TwitterOAuth instance, with two new parameters we got in twitter_login.php
	$twitteroauth = new TwitterOAuth($app_key, $app_secret, $_SESSION['oauth_token'], $_SESSION['oauth_token_secret']);

    // Let's request the access token
	$access_token = $twitteroauth->getAccessToken($_GET['oauth_verifier']);

    // Let's get the user's info
	$user_info = $twitteroauth->get('account/verify_credentials');

	if(isset($user_info->error) || $user_info->id == 0 || !is_numeric($user_info->id)){
		// Something's wrong, go back to square 1
		header('Location: twitter_login.php');
	} else {
		// Let's find the user by its ID
		$query = mysql_query("SELECT * FROM tokens WHERE userid = ". $user_info->id);
		$result = mysql_fetch_array($query);

        if (!($stmt = $mysqli->prepare("SELECT * FROM tokens WHERE userid = ?"))) {
            echo "Prepare failed: (" . $mysqli->errno . ") " . $mysqli->error;
        }
        if (!$stmt->bind_param("i", {$user_info->id})) {
            echo "Binding parameters failed: (" . $stmt->errno . ") " . $stmt->error;
        }
        if (!$stmt->execute()) {
            echo "Execute failed: (" . $stmt->errno . ") " . $stmt->error;
        }
        $result = $stmt->get_result();

		// If not, let's add it to the database
		if(empty($result)){

            if (!($stmt = $mysqli->prepare("INSERT INTO tokens (userid, oauth_token, oauth_secret, added) VALUES (?, ?, ?, NOW())"))) {
                echo "Prepare failed: (" . $mysqli->errno . ") " . $mysqli->error;
            }
            if (!$stmt->bind_param("iss", {$user_info->id},{$access_token['oauth_token']},{$access_token['oauth_token_secret']})) {
               echo "Binding parameters failed: (" . $stmt->errno . ") " . $stmt->error;
            }
            if (!$stmt->execute()) {
                echo "Execute failed: (" . $stmt->errno . ") " . $stmt->error;
            }

            $result = $mysqli->query("SELECT * FROM tokens WHERE id = " . $mysqli->insert_id);


		} else {
			// Update the tokens
            if (!($stmt = $mysqli->prepare("UPDATE tokens SET oauth_token = ?, oauth_secret = ?, accessed = NOW() WHERE userid = ?"))) {
                echo "Prepare failed: (" . $mysqli->errno . ") " . $mysqli->error;
            }
            if (!$stmt->bind_param("ssi", {$access_token['oauth_token']},{$access_token['oauth_token_secret']},{$user_info->id})) {
                echo "Binding parameters failed: (" . $stmt->errno . ") " . $stmt->error;
            }
            if (!$stmt->execute()) {
                echo "Execute failed: (" . $stmt->errno . ") " . $stmt->error;
            }
		}

        $_SESSION['access_token'] = $access_token;
		$_SESSION['id'] = $result['id'];
		$_SESSION['oauth_uid'] = $result['userid'];
		$_SESSION['oauth_token'] = $result['oauth_token'];
		$_SESSION['oauth_token_secret'] = $result['oauth_secret'];
 
		header('Location: step1.php');
	}
} else {
    // Something's missing, go back to square 1
    header('Location: twitter_login.php');
}

?>

