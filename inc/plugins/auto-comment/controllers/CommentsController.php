<?php
namespace Plugins\AutoComment;

// Disable direct access
if (!defined('APP_VERSION')) 
    die("Yo, what's up?");

/**
 * Comments Controller
 */
class CommentsController extends \Controller
{
    /**
     * Process
     */
    public function process()
    {
        $AuthUser = $this->getVariable("AuthUser");
        $Route = $this->getVariable("Route");
        $this->setVariable("idname", "auto-comment");

        // Auth
        if (!$AuthUser){
            header("Location: ".APPURL."/login");
            exit;
        } else if ($AuthUser->isExpired()) {
            header("Location: ".APPURL."/expired");
            exit;
        }

        $user_modules = $AuthUser->get("settings.modules");
        if (!is_array($user_modules) || !in_array($this->getVariable("idname"), $user_modules)) {
            // Module is not accessible to this user
            header("Location: ".APPURL."/post");
            exit;
        }


        // Get account
        $Account = \Controller::model("Account", $Route->params->id);
        if (!$Account->isAvailable() || 
            $Account->get("user_id") != $AuthUser->get("id")) 
        {
            header("Location: ".APPURL."/e/".$this->getVariable("idname"));
            exit;
        }
        $this->setVariable("Account", $Account);

        // Get Schedule
        require_once PLUGINS_PATH."/".$this->getVariable("idname")."/models/ScheduleModel.php";
        $Schedule = new ScheduleModel([
            "account_id" => $Account->get("id"),
            "user_id" => $Account->get("user_id")
        ]);
        $this->setVariable("Schedule", $Schedule);

        if (\Input::post("action") == "save") {
            $this->save();
        }

        $this->view(PLUGINS_PATH."/".$this->getVariable("idname")."/views/comments.php", null);
    }


    /**
     * Save schedule
     * @return mixed 
     */
    private function save()
    {
        $this->resp->result = 0;
        $AuthUser = $this->getVariable("AuthUser");
        $Account = $this->getVariable("Account");
        $Schedule = $this->getVariable("Schedule");


        // Emojione Client
        $Emojione = new \Emojione\Client(new \Emojione\Ruleset());

        // Comments
        $raw_comments = @json_decode(\Input::post("comments"));
        $valid_comments = [];
        if ($raw_comments) {
            foreach ($raw_comments as $c) {
                $valid_comments[] = $Emojione->toShort($c);
            }
        }
        $comments = json_encode($valid_comments);

        $Schedule->set("comments", $comments)
                 ->save();

        $this->resp->msg = __("Changes saved!");
        $this->resp->result = 1;
        $this->jsonecho();
    }
}
