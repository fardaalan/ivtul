<?php 
require_once APPPATH.'/config/db.config.php';
require_once APPPATH.'/config/i18n.config.php';
require_once APPPATH.'/config/common.config.php';

// ASCII Secure random crypto key
define("CRYPTO_KEY", "def0000097f886338ec09c835236481c197b71d99829d75e9bf3bff9941c45d1df48feda7f0a0f261f420cbfad0dc02176d852ee4d67ef7061b557fb72ec988dd24510eb");

// General purpose salt
define("NP_SALT", "oGck70yWgmfUQYpf");


// Path to instagram sessions directory
define("SESSIONS_PATH", APPPATH . "/sessions");
// Path to temporary files directory
define("TEMP_PATH", ROOTPATH . "/assets/uploads/temp");


// Path to themes directory
define("THEMES_PATH", ROOTPATH . "/inc/themes");
// URI of themes directory
define("THEMES_URL", APPURL . "/inc/themes");


// Path to plugins directory
define("PLUGINS_PATH", ROOTPATH . "/inc/plugins");
// URI of plugins directory
define("PLUGINS_URL", APPURL . "/inc/plugins");

// Path to ffmpeg binary executable
// NULL means it's been installed on global path
// If you set the value other than null, then it will only be 
// validated during posting the videos
define("FFMPEGBIN", NULL);

// Path to ffprobe binary executable
// NULL means it's been installed on global path
// If you set the value other than null, then it will only be 
// validated during posting the videos
define("FFPROBEBIN", NULL);
