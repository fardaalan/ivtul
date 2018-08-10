<?php
/**
 * Challenge Controller
 */
class ChallengeController extends Controller
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


        if (md5($Route->params->id.NP_SALT) != $Route->params->hash) {
            // Invalid hash
            header("Location: ".APPURL."/accounts");
            exit;
        }


        $Challenge = Controller::model("Challenge", $Route->params->id);
        if (!$Challenge->isAvailable() || 
            $Challenge->get("user_id") != $AuthUser->get("id")) {
            header("Location: ".APPURL."/accounts/new");
            exit;
        }


        $Account = Controller::model("Account", $Challenge->get("account_id"));
        if ($Account->get("user_id") != $AuthUser->get("id") ||
            !$Account->get("login_required")) {
            // Unexpected
            header("Location: ".APPURL."/accounts/new");
            exit;
        }

        $this->setVariable("Account", $Account)
             ->setVariable("Challenge", $Challenge);

        
        $this->sendVerificationCode();

        if (Input::post("action") == "approve") {
            $this->approveVerificationCode();
        }

        $this->view("challenge");
    }


    /**
     * Send verification code
     * @return boolean
     */
    private function sendVerificationCode()
    {
        $Route = $this->getVariable("Route");
        $Account = $this->getVariable("Account");
        $AuthUser = $this->getVariable("AuthUser");
        $Challenge = $this->getVariable("Challenge");


        if ($Challenge->get("resource_expired")) {
            $this->setVariable("error", __("Requested resource does not exist."));
            return false;
        }


        $replay = false;
        if ($Challenge->get("is_sent")) {
            if (strtotime($Challenge->get("sent_date")) + 60 < time()) {
                $replay = true;
            } else {
                return true;
            }
        }


        $choice = 1; // via email
        if ($Challenge->get("is_sent")) {
            $choice = $Challenge->get("choice");
        } else if (isset($Route->params->choice)) {
            $choice = $Route->params->choice;
        }

        if (!in_array($choice, [0,1])) {
            $choice = 1;
        }

        // Decrypt pass.
        try {
            $password = \Defuse\Crypto\Crypto::decrypt($Account->get("password"), 
                        \Defuse\Crypto\Key::loadFromAsciiSafeString(CRYPTO_KEY));
        } catch (Exception $e) {
            $this->setVariable("error", __("Encryption error"));
            return false;
        }


        $storageConfig = [
            "storage" => "file",
            "basefolder" => SESSIONS_PATH."/".$AuthUser->get("id")."/",
        ];

        $Instagram = new \InstagramAPI\Instagram(false, false, $storageConfig);
        $Instagram->setVerifySSL(SSL_ENABLED);

        if ($Account->get("proxy")) {
            $Instagram->setProxy($Account->get("proxy"));
        }

        try {
            $Instagram->setUser($Account->get("username"), $password);
        } catch (\Exception $e) {
            $this->setVariable("error", $e->getMessage());
            return false;
        }

        try {
            $resp = $this->_sendVerificationCode($Instagram, $Challenge, $choice, $replay);
        } catch (\Exception $e) {
            $this->setVariable("error", $e->getMessage());

            if (stripos($e->getMessage(), "Requested resource does not exist") !== false) {
                $Challenge->set("resource_expired", 1)->save();
            }

            return false;
        }

        if (!empty($resp->fullResponse->step_data->phone_number_preview)) {
            $Challenge->set("contact_preview", $resp->fullResponse->step_data->phone_number_preview);
        } else if (!empty($resp->fullResponse->step_data->contact_point)) {
            $Challenge->set("contact_preview", $resp->fullResponse->step_data->contact_point);
        }

        $Challenge->set("is_sent", 1)
                  ->set("sent_date", date("Y-m-d H:i:s"))
                  ->set("choice", $choice)
                  ->save();

        return true;
    }


    private function _sendVerificationCode($Instagram, $Challenge, $choice = 1, $replay = false)
    {
        try {
            $resp = $Instagram->sendChallengeVerificationCode(
                $Challenge->get("instagram_id"),
                $Challenge->get("challenge_id"),
                $choice,
                $replay);
        } catch (\Exception $e) {
            if (stripos($e->getMessage(), "Select a valid choice. 0 is not one of the available choices.") !== false && $choice != 1) {
                try {
                    $Challenge->set("choice", 1)->save();
                    $resp = $this->_sendVerificationCode($Instagram, $Challenge, 1, $replay);
                } catch (\Exception $e) {
                    throw $e;
                }
            } else {
                throw $e;
            }
        }

        return $resp;
    }



    /**
     * Approve verification code
     * @return void 
     */
    private function approveVerificationCode()
    {
        $this->resp->result = 0;
        $Route = $this->getVariable("Route");
        $Account = $this->getVariable("Account");
        $AuthUser = $this->getVariable("AuthUser");
        $Challenge = $this->getVariable("Challenge");

        $security_code = Input::post("security-code");


        // Check required data
        if (!$security_code) {
            $this->resp->msg = __("Missing some of required data.");
            $this->jsonecho();
        }


        // Decrypt pass.
        try {
            $password = \Defuse\Crypto\Crypto::decrypt($Account->get("password"), 
                        \Defuse\Crypto\Key::loadFromAsciiSafeString(CRYPTO_KEY));
        } catch (Exception $e) {
            $this->setVariable("error", __("Encryption error"));
            return false;
        }
        

        $storageConfig = [
            "storage" => "file",
            "basefolder" => SESSIONS_PATH."/".$AuthUser->get("id")."/",
        ];

        $Instagram = new \InstagramAPI\Instagram(false, false, $storageConfig);
        $Instagram->setVerifySSL(SSL_ENABLED);

        if ($Account->get("proxy")) {
            $Instagram->setProxy($Account->get("proxy"));
        }
        
        try {
            $Instagram->setUser($Account->get("username"), $password);
            $resp = $Instagram->approveChallengeVerificationCode(
                $Challenge->get("instagram_id"),
                $Challenge->get("challenge_id"),
                $security_code);
        } catch (\Exception $e) {
            if (stripos($e->getMessage(), "Please check the code which has been sent you and try again.") !== false) {
                $this->resp->msg = __("Please check the code which has been sent you and try again.");
            } else {
                $this->resp->msg = $e->getMessage();
            }
            $this->jsonecho();
        }


        $Challenge->remove();
        $Account->set("login_required", 0)
                ->set("last_login", date("Y-m-d H:i:s", time() - 3600))
                ->save();

        $this->resp->result = 1;
        $this->resp->redirect = APPURL."/accounts";
        $this->jsonecho();
    }
}