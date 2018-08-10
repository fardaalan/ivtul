<?php
/**
 * Account Controller
 */
class AccountController extends Controller
{
    /**
     * Process
     */
    public function process()
    {
        $AuthUser = $this->getVariable("AuthUser");
        $Route = $this->getVariable("Route");

        // Auth
        if (!$AuthUser){
            header("Location: ".APPURL."/login");
            exit;
        } else if ($AuthUser->isExpired()) {
            header("Location: ".APPURL."/expired");
            exit;
        }


        // Get accounts
        $Accounts = Controller::model("Accounts");
            $Accounts->setPage(Input::get("page"))
                     ->where("user_id", "=", $AuthUser->get("id"))
                     ->fetchData();

        // Account
        if (isset($Route->params->id)) {
            $Account = Controller::model("Account", $Route->params->id);
            if (!$Account->isAvailable() || 
                $Account->get("user_id") != $AuthUser->get("id")) 
            {
                header("Location: ".APPURL."/accounts");
                exit;
            }
        } else {
            $max_accounts = $AuthUser->get("settings.max_accounts");
            if ($Accounts->getTotalCount() >= $max_accounts && $max_accounts != "-1") {
                // Max. limit exceeds
                header("Location: ".APPURL."/accounts");
                exit;
            }

            $Account = Controller::model("Account"); // new account model
        }


        // Set view variables
        $this->setVariable("Accounts", $Accounts)
             ->setVariable("Account", $Account)
             ->setVariable("Settings", Controller::model("GeneralData", "settings"));


        if (Input::post("action") == "save") {
            $this->save();
        }
        if (Input::post("action") == "save2") {
            $this->save2();
        }
        $this->view("account");
    }


    /**
     * Save (new|edit)
     * @return void 
     */
    private function save()
    {
        $this->resp->result = 0;
        $Route = $this->getVariable("Route");
        $AuthUser = $this->getVariable("AuthUser");
        $Account = $this->getVariable("Account");
        $Settings = $this->getVariable("Settings");
        $IpInfo = $this->getVariable("IpInfo");

        $username = strtolower(Input::post("username"));
        $password = Input::post("password");


        // Check if this is new or not
        $is_new = !$Account->isAvailable();


        // Check required data
        if (!$username || !$password) {
            $this->resp->msg = __("Missing some of required data.");
            $this->jsonecho();
        }


        // Prevent emails as username
        if (filter_var($username, FILTER_VALIDATE_EMAIL)) {
            $this->resp->msg = __("Please include username instead of the email.");
            $this->jsonecho();
        }

        
        // Check username
        $check_username = true;
        if ($Account->isAvailable() && $Account->get("username") == $username) {
            $check_username = false;
        }

        if ($check_username) {
            foreach ($this->getVariable("Accounts")->getData() as $a) {
                if ($a->username == $username) {
                    // This account is already exists (for the current user)
                    $this->resp->msg = __("Account is already exists!");
                    $this->jsonecho();
                    break;
                }
            }
        }


        // Check proxy
        $proxy = null;
        $is_system_proxy = false;
        if ($Settings->get("data.proxy")) {
            if (Input::post("proxy") && $Settings->get("data.user_proxy")) {
                $proxy = Input::post("proxy");

                if (!isValidProxy($proxy)) {
                    $this->resp->msg = __("Proxy is not valid or active!");
                    $this->jsonecho();
                }
            } else {
                $user_country = !empty($IpInfo->countryCode) 
                              ? $IpInfo->countryCode : null;
                $countries = [];
                if (!empty($IpInfo->neighbours)) {
                    $countries = $IpInfo->neighbours;
                }
                array_unshift($countries, $user_country);
                $proxy = ProxiesModel::getBestProxy($countries);
                $is_system_proxy = true;
            }
        }


        // Encrypt the password
        try {
            $passhash = Defuse\Crypto\Crypto::encrypt($password, 
                        Defuse\Crypto\Key::loadFromAsciiSafeString(CRYPTO_KEY));
        } catch (\Exception $e) {
            $this->resp->msg = __("Encryption error");
            $this->jsonecho();
        }


        // Account defaults
        $Account->set("user_id", $AuthUser->get("id"))
                ->set("password", $passhash)
                ->set("proxy", $proxy ? $proxy : "")
                ->set("login_required", 1);
        if ($Account->get("username") != $username) {
            $Account->set("instagram_id", uniqid("instagram_"))
                    ->set("username", $username);
        }
        $Account->save();
        

        $storageConfig = [
            "storage" => "file",
            "basefolder" => SESSIONS_PATH."/".$AuthUser->get("id")."/",
        ];

        $Instagram = new \InstagramAPI\Instagram(false, false, $storageConfig);
        $Instagram->setVerifySSL(SSL_ENABLED);

        if ($proxy) {
            $Instagram->setProxy($proxy);
        }
        
        try {
            $Instagram->setUser($username, $password);
            $login_resp = $Instagram->login(true);
        } catch (InstagramAPI\Exception\SettingsException $e) {
            $this->resp->msg = $e->getMessage();
            $this->jsonecho();

            if ($is_new) {
                $Account->remove();
            }
        } catch (InstagramAPI\Exception\CheckpointRequiredException $e) {
            if ($e->getResponse() && !empty($e->getResponse()->challenge->api_path)) {
                $iresp = $e->getResponse();
                $challenge_path = $iresp->challenge->api_path;
                $parts = explode("/", trim($challenge_path, "/"));

                if (empty($parts[1]) || empty($parts[2])) {
                    $this->resp->msg = __("Couldn't detect account and/or challenge id");
                    $this->jsonecho();
                }

                $instagram_id = $parts[1];
                $challenge_id = $parts[2];

                try {
                    $this->checkChallengeTable();
                } catch (\Exception $e) {
                    $this->resp->msg = $e->getMessage();
                    $this->jsonecho();
                }

                $Challenge = Controller::model("Challenge");
                $Challenge->set("user_id", $AuthUser->get("id"))
                          ->set("account_id", $Account->get("id"))
                          ->set("instagram_id", $instagram_id)
                          ->set("challenge_id", $challenge_id)
                          ->save();

                $Account->set("instagram_id", $instagram_id)
                        ->save();

                $this->resp->result = 2;
                $this->resp->msg = __("Verification code is required for logging in. <br /> Please select a method to receive the verification code.");
                $this->resp->links = [
                    [   
                        "name" => "sms",
                        "label" => __("Send via SMS"),
                        "uri" => APPURL."/accounts/challenge/".$Challenge->get("id").".0.".md5($Challenge->get("id").NP_SALT)
                    ],
                    [
                        "name" => "email",
                        "label" => __("Send via Email"),
                        "uri" => APPURL."/accounts/challenge/".$Challenge->get("id").".1.".md5($Challenge->get("id").NP_SALT)
                    ]
                ];
            } else {
                $this->resp->result = 2;
                $this->resp->msg = __("Please goto <a href='http://instagram.com' target='_blank'>instagram.com</a> and pass checkpoint. After approving the login click the button below and your account again.");
                $this->resp->links = [
                    [
                        "name" => "ok",
                        "label" => __("I approved the login"),
                        "uri" => APPURL."/accounts/".$Account->get("id")
                    ]
                ];
            }

            $this->jsonecho();
        } catch (InstagramAPI\Exception\InstagramException $e) {
            $msg = $e->getMessage();
            if (strpos($msg, "The password you entered is incorrect") !== false) {
                $msg = __("The password you entered is incorrect. Please try again.");
            } else if (strpos($msg, "Please check your username and try again") !== false) {
                $msg = __("The username you entered doesn't appear to belong to an account. Please check your username and try again.");
            }

            if ($is_new) {
                $Account->remove();
            }

            $this->resp->msg = $msg;
            $this->jsonecho();
        } catch (\Exception $e) {

            if ($is_new) {
                $Account->remove();
            }
            $this->resp->msg = __("Oops! Something went wrong. Please try again later!");
            $this->jsonecho();
        }


        

        // Save data
        $Account->set("instagram_id", $Instagram->account_id)
                ->set("username", $login_resp->logged_in_user->username)
                ->set("login_required", 0)
                ->save();


        // Update proxy use count
        if ($proxy && $is_system_proxy == true) {
            $Proxy = Controller::model("Proxy", $proxy);
            if ($Proxy->isAvailable()) {
                $Proxy->set("use_count", $Proxy->get("use_count") + 1)
                      ->save();
            }
        }


        $this->resp->result = 1;
        if ($is_new) {
            $this->resp->redirect = APPURL."/accounts";
        } else {
            $this->resp->msg = __("Changes saved!");
        }
        $this->jsonecho();
    }

 private function save2()
    {
        $this->resp->result = 0;
        $Route = $this->getVariable("Route");
        $AuthUser = $this->getVariable("AuthUser");
        $Account = $this->getVariable("Account");
        $Settings = $this->getVariable("Settings");
        $IpInfo = $this->getVariable("IpInfo");

        $username = strtolower(Input::post("username"));
        $password = Input::post("password");


        // Check if this is new or not
        $is_new = !$Account->isAvailable();


        // Check required data
        if (!$username || !$password) {
            $this->resp->msg = __("Missing some of required data.");
            $this->jsonecho();
        }


        // Prevent emails as username
        if (filter_var($username, FILTER_VALIDATE_EMAIL)) {
            $this->resp->msg = __("Please include username instead of the email.");
            $this->jsonecho();
        }

        
        // Check username
        $check_username = true;
        if ($Account->isAvailable() && $Account->get("username") == $username) {
            $check_username = false;
        }

        if ($check_username) {
            foreach ($this->getVariable("Accounts")->getData() as $a) {
                if ($a->username == $username) {
                    // This account is already exists (for the current user)
                    $this->resp->msg = __("Account is already exists!");
                    $this->jsonecho();
                    break;
                }
            }
        }


        // Check proxy
        $proxy = null;
        $is_system_proxy = false;
        if ($Settings->get("data.proxy")) {
            if (Input::post("proxy") && $Settings->get("data.user_proxy")) {
                $proxy = Input::post("proxy");

                if (!isValidProxy($proxy)) {
                    $this->resp->msg = __("Proxy is not valid or active!");
                    $this->jsonecho();
                }
            } else {
                $user_country = !empty($IpInfo->countryCode) 
                              ? $IpInfo->countryCode : null;
                $countries = [];
                if (!empty($IpInfo->neighbours)) {
                    $countries = $IpInfo->neighbours;
                }
                array_unshift($countries, $user_country);
                $proxy = ProxiesModel::getBestProxy($countries);
                $is_system_proxy = true;
            }
        }


        // Encrypt the password
        try {
            $passhash = Defuse\Crypto\Crypto::encrypt($password, 
                        Defuse\Crypto\Key::loadFromAsciiSafeString(CRYPTO_KEY));
        } catch (\Exception $e) {
            $this->resp->msg = __("Encryption error");
            $this->jsonecho();
        }


        // Account defaults
        $Account->set("user_id", $AuthUser->get("id"))
                ->set("password", $passhash)
                ->set("proxy", $proxy ? $proxy : "")
                ->set("login_required", 1);
        if ($Account->get("username") != $username) {
            $Account->set("instagram_id", uniqid("instagram_"))
                    ->set("username", $username);
        }
        $Account->save();
        

        $storageConfig = [
            "storage" => "file",
            "basefolder" => SESSIONS_PATH."/".$AuthUser->get("id")."/",
        ];

        $Instagram = new \InstagramAPI\Instagram(false, false, $storageConfig);
        $Instagram->setVerifySSL(SSL_ENABLED);

        if ($proxy) {
            $Instagram->setProxy($proxy);
        }
        
        try {
            $Instagram->setUser($username, $password);
            $login_resp = $Instagram->login_facebook(true);
        } catch (InstagramAPI\Exception\SettingsException $e) {
            $this->resp->msg = $e->getMessage();
            $this->jsonecho();

            if ($is_new) {
                $Account->remove();
            }
        } catch (InstagramAPI\Exception\CheckpointRequiredException $e) {
            if ($e->getResponse() && !empty($e->getResponse()->challenge->api_path)) {
                $iresp = $e->getResponse();
                $challenge_path = $iresp->challenge->api_path;
                $parts = explode("/", trim($challenge_path, "/"));

                if (empty($parts[1]) || empty($parts[2])) {
                    $this->resp->msg = __("Couldn't detect account and/or challenge id");
                    $this->jsonecho();
                }

                $instagram_id = $parts[1];
                $challenge_id = $parts[2];

                try {
                    $this->checkChallengeTable();
                } catch (\Exception $e) {
                    $this->resp->msg = $e->getMessage();
                    $this->jsonecho();
                }

                $Challenge = Controller::model("Challenge");
                $Challenge->set("user_id", $AuthUser->get("id"))
                          ->set("account_id", $Account->get("id"))
                          ->set("instagram_id", $instagram_id)
                          ->set("challenge_id", $challenge_id)
                          ->save();

                $Account->set("instagram_id", $instagram_id)
                        ->save();

                $this->resp->result = 2;
                $this->resp->msg = __("Verification code is required for logging in. <br /> Please select a method to receive the verification code.");
                $this->resp->links = [
                    [   
                        "name" => "sms",
                        "label" => __("Send via SMS"),
                        "uri" => APPURL."/accounts/challenge/".$Challenge->get("id").".0.".md5($Challenge->get("id").NP_SALT)
                    ],
                    [
                        "name" => "email",
                        "label" => __("Send via Email"),
                        "uri" => APPURL."/accounts/challenge/".$Challenge->get("id").".1.".md5($Challenge->get("id").NP_SALT)
                    ]
                ];
            } else {
                $this->resp->result = 2;
                $this->resp->msg = __("Please goto <a href='http://instagram.com' target='_blank'>instagram.com</a> and pass checkpoint. After approving the login click the button below and your account again.");
                $this->resp->links = [
                    [
                        "name" => "ok",
                        "label" => __("I approved the login"),
                        "uri" => APPURL."/accounts/".$Account->get("id")
                    ]
                ];
            }

            $this->jsonecho();
        } catch (InstagramAPI\Exception\InstagramException $e) {
            $msg = $e->getMessage();
            if (strpos($msg, "The password you entered is incorrect") !== false) {
                $msg = __("The password you entered is incorrect. Please try again.");
            } else if (strpos($msg, "Please check your username and try again") !== false) {
                $msg = __("The username you entered doesn't appear to belong to an account. Please check your username and try again.");
            }else{
				$msg = __("Incorrect token, make sure token is correct");
            }

            if ($is_new) {
                $Account->remove();
            }

            $this->resp->msg = $msg;
            $this->jsonecho();
        } catch (\Exception $e) {

            if ($is_new) {
                $Account->remove();
            }
            $this->resp->msg = __("Oops! Something went wrong. Please try again later!");
            $this->jsonecho();
        }


        

        // Save data
        $Account->set("instagram_id", $Instagram->account_id)
                ->set("username", $login_resp->logged_in_user->username)
                ->set("login_required", 0)
                ->save();


        // Update proxy use count
        if ($proxy && $is_system_proxy == true) {
            $Proxy = Controller::model("Proxy", $proxy);
            if ($Proxy->isAvailable()) {
                $Proxy->set("use_count", $Proxy->get("use_count") + 1)
                      ->save();
            }
        }


        $this->resp->result = 1;
        if ($is_new) {
            $this->resp->redirect = APPURL."/accounts";
        } else {
            $this->resp->msg = __("Changes saved!");
        }
        $this->jsonecho();
    }


    /**
     * Check if table exists,
     * if not then creat
     * @return null 
     */
    private function checkChallengeTable()
    {
        $table_name = TABLE_PREFIX."challenges";

        $pdo = DB::pdo();
        $stmt = $pdo->prepare("SHOW TABLES LIKE ?");
        $stmt->execute([$table_name]);
        if ($stmt->rowCount() > 0) {
            return true;
        }

        try {
            $sql = "CREATE TABLE " . $table_name . " ( 
                `id` INT NOT NULL AUTO_INCREMENT , 
                `user_id` INT NOT NULL , 
                `account_id` INT NOT NULL , 
                `instagram_id` varchar(255) NOT NULL , 
                `challenge_id` varchar(255) NOT NULL , 
                `choice` INT NOT NULL , 
                `resource_expired` BOOLEAN NOT NULL , 
                `contact_preview` varchar(100) NOT NULL , 
                `is_sent` BOOLEAN NOT NULL , 
                `sent_date` DATETIME NOT NULL , 
                `date` DATETIME NOT NULL , 
                PRIMARY KEY (`id`)
            ) ENGINE = InnoDB;";

            $sql .= "ALTER TABLE `".$table_name."` 
                ADD CONSTRAINT `".uniqid("ibfk_")."` FOREIGN KEY (`user_id`) 
                REFERENCES `".TABLE_PREFIX.TABLE_USERS."`(`id`) 
                ON DELETE CASCADE ON UPDATE CASCADE;";

            $sql .= "ALTER TABLE `".$table_name."` 
                        ADD CONSTRAINT `".uniqid("ibfk_")."` FOREIGN KEY (`account_id`) 
                        REFERENCES `".TABLE_PREFIX.TABLE_ACCOUNTS."`(`id`) 
                        ON DELETE CASCADE ON UPDATE CASCADE;";


            DB::query($sql);
        } catch (\Exception $e) {
            throw new \Exception(__("Couldn't find or challenges files table"));
        }
    }
}