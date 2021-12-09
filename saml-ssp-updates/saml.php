<?php

require_once "hooks.php";

if (isset($_POST['SAMLResponse']) && $_GET['do'] == 'ext') {
    $_POST['__CSRFToken__'] = $_SESSION['csrf']['token'];
}

class SAMLSSPBase {
    public $id;
    protected $config;
    protected $samlauth = null;

    public function __construct($config) {
        $this->config = $config;
    }

    public static function loadSimplesamlphp($cfg) {
        $simpleSAMLphpPath = $cfg->get('saml-ssp-path');
        if (!empty($simpleSAMLphpPath) && substr($simpleSAMLphpPath, -1) != '/') {
            $simpleSAMLphpPath .= '/';
        }

        require_once ($simpleSAMLphpPath."lib/_autoload.php");
    }

    public static function getSAMLAuth($cfg, $authtype = "client") {
        SAMLSSPBase::loadSimplesamlphp($cfg);
        $authsource = $cfg->get('saml-ssp-'.$authtype.'-authentication-source');
        if (class_exists('SimpleSAML_Auth_Simple')) {
            $samlauth = new SimpleSAML_Auth_Simple($authsource);
        } else {
            $samlauth = new \SimpleSAML\Auth\Simple($authsource);
        }
        return $samlauth;
    }

    public function triggerAuth() {
        $self = $this;
        if (isset($_GET['bk']) && strcmp($_GET['bk'], 'samlssp.staff') === 0) {
            $relayState = SAMLSSPBase::getBaseURL().'/scp/login.php?do=ext&bk=samlssp.staff';
            $this->samlauth = SAMLSSPBase::getSAMLAuth($this->config, 'staff');
        } else {
            $relayState = SAMLSSPBase::getBaseURL().'/login.php?do=ext&bk=samlssp';
            $this->samlauth = SAMLSSPBase::getSAMLAuth($this->config, 'client');
        }

        try {
            if (!$this->samlauth->isAuthenticated()) {
                $ds = $this->config->get('saml-ssp-discovery-service-url');
                if (empty($ds)) {
                    $this->login($relayState);
                } else if (!isset($_GET['entityID'])) {
                    $spEntityId = $this->samlauth->getAuthSource()->getEntityId();
                    Http::redirect($ds.'?entityID='.urlencode($spEntityId).'&return='.urlencode($relayState));
                } else {
                    $this->login($relayState, $_GET['entityID']);
                }
            } else {
                $this->acs();
            }
        } catch (\SimpleSAML\Error\Exception $e) {
            echo $e->getMessage();
            exit();
        } catch (SimpleSAML_Error_Exception $e) {
            echo $e->getMessage();
            exit();
        }
    }

    public function getUser() {
        return isset($_SESSION[':samlssp']['user']) ? $_SESSION[':samlssp']['user'] : '';
    }

    public function getEmail() {
        return isset($_SESSION[':samlssp']['email']) ? $_SESSION[':samlssp']['email'] : '';
    }

    public function getPhone() {
        return isset($_SESSION[':samlssp']['phone']) ? $_SESSION[':samlssp']['phone'] : '';
    }

    public function getFullName() {
        return isset($_SESSION[':samlssp']['name']) ? $_SESSION[':samlssp']['name'] : '';
    }

    public function getFirstName() {
        return isset($_SESSION[':samlssp']['firstname']) ? $_SESSION[':samlssp']['firstname'] : '';
    }

    public function getLastName() {
        return isset($_SESSION[':samlssp']['lastname']) ? $_SESSION[':samlssp']['lastname'] : '';
    }

    public function getOrganization() {
        return isset($_SESSION[':samlssp']['organization']) ? $_SESSION[':samlssp']['organization'] : '';
    }

    public function getSystemRole() {
        return isset($_SESSION[':samlssp']['systemrole']) ? $_SESSION[':samlssp']['systemrole'] : null;
    }

    public function getRoles() {
        return isset($_SESSION[':samlssp']['roles']) ? $_SESSION[':samlssp']['roles'] : null;
    }

    public function getDepartaments() {
        return isset($_SESSION[':samlssp']['departaments']) ? $_SESSION[':samlssp']['departaments'] : null;
    }

    public function getTeams() {
        return isset($_SESSION[':samlssp']['teams']) ? $_SESSION[':samlssp']['teams'] : null;
    }

    public function getDefaultTimezone() {
        global $cfg;
        return $cfg->getDefaultTimezone();
    }

    public function getProfile() {
        return array(
            'user' => $_SESSION[':samlssp']['user'],
            'email' => $_SESSION[':samlssp']['email'],
            'name' => $_SESSION[':samlssp']['name'],
            'phone' => $_SESSION[':samlssp']['phone']
        );
    }

    public function getNameId() {
        return isset($_SESSION[':samlssp']['nameid']) ? $_SESSION[':samlssp']['nameid'] : null;
    }

    public static function getBaseURL() {
        global $cfg;
        return $cfg->getBaseUrl();
    }

    public function getRelayState() {
        return isset($_SESSION[':samlssp']['relaystate']) ? $_SESSION[':samlssp']['relaystate'] : null;
    }

    public function removeRelayState() {
        unset($_SESSION[':samlssp']['relaystate']);
    }

    public function getOrganizationNameValue($autocreate = false) {
        $orgName = $this->getOrganization();

        if ($autocreate && empty($orgName)) {
            $defaultOrgName = $this->config->get('saml-ssp-options-organization');
            if ($defaultOrgName !== "0") {
                $orgName = $defaultOrgName;
            }
        }

        return $orgName;
    }

    public function getSystemRoleValue($autocreate = false) {
        $isAdmin = null;

        $systemRoleValue = $this->getSystemRole();
        if ($autocreate  && empty($systemRoleValue) || !in_array($systemRoleValue, array("admin", "agent"))) {
            $systemRoleValue = $this->config->get('saml-ssp-options-system-role');
        }
        if (strcmp($systemRoleValue, 'agent') === 0) {
            $isAdmin = 0;
        } else if (strcmp($systemRoleValue, 'admin') === 0) {
            $isAdmin = 1;
        }
        return $isAdmin;
    }

    public function getDeptIdValues($autocreate = false) {
        $deptIds = $this->getDepartaments();
        if ($autocreate && empty($deptIds)) {
            $defaultDepartament = $this->config->get('saml-ssp-options-primary-departament');
            if ($defaultDepartament !== "0") {
                $deptIds[] = $defaultDepartament;
            }

            if (count($deptIds) == 1) {
                $defaultDepartament2 = $this->config->get('saml-ssp-options-secondary-departament');
                if ($defaultDepartament2 !== "0") {
                    $deptIds[] = $defaultDepartament2;
                }
            }
        }

        return $deptIds;
    }

    public function getRoleIdValues($autocreate = false) {
        $roleIds = $this->getRoles();
        if ($autocreate && empty($roleIds)) {
            $defaultRole = $this->config->get('saml-ssp-options-primary-role');
            if ($defaultRole !== "0") {
                $roleIds[] = $defaultRole;
            }

            if (count($roleIds) == 1) {
                $defaultRole2 = $this->config->get('saml-ssp-options-secondary-role');
                if ($defaultRole2 !== "0") {
                    $roleIds[] = $defaultRole2;
                }
            }
        }

        return $roleIds;
    }

    public function getTeamIdValues($autocreate = false) {
        $teamIds = $this->getTeams();
        if ($autocreate && empty($teamIds)) {
            $defaultTeam = $this->config->get('saml-ssp-options-team');
            if ($defaultTeam !== "0") {
                $teamIds = array($defaultTeam);
            }
        }

        return $teamIds;
    }

/*
    public function getIdsOfDeptsWithAlertsEnabled() {
        $ids = array();
        $value = $this->config->get('saml-ssp-options-enable-alerts-on-dept');
        if (!empty($value)) {
            $ids = explode(",", $value);
        }
        return $ids;
    }
*/
    public function getIdsOfTeamsWithAlertsEnabled() {
        $ids = array();
        $value = $this->config->get('saml-ssp-options-enable-alerts-on-team');
        if (!empty($value)) {
            $ids = explode(",", $value);
        }
        return $ids;
    }

    public function login($relayState, $entityId) {
        $params = ['ReturnTo' => $relayState];
        if (!empty($entityId)) {
            $params['saml:idp'] = $entityId;
        }
        $this->samlauth->login($params);
    }

    public static function samlLogout($cfg, $mode) {
        $target = SAMLSSPBase::getBaseURL();
        if (isset($mode) && strcmp($mode, 'samlssp.staff') === 0) {
            $_GET['bk'] = 'samlssp.staff';
        }

        if ((isset($_GET['bk']) && strcmp($_GET['bk'], 'samlssp.staff') === 0)) {
            $target .= '/scp/';
            $samlauth = SAMLSSPBase::getSAMLAuth($cfg, 'staff');
        } else {
            $samlauth = SAMLSSPBase::getSAMLAuth($cfg, 'client');
        }

        if ($samlauth->isAuthenticated()) {
            $samlauth->logout();
        }
    }

    public function acs() {
        $processingStaff = false;
        if (isset($_GET['bk']) && strcmp($_GET['bk'], 'samlssp.staff') === 0) {
            $processingStaff = true;
        }

        if ($this->samlauth->isAuthenticated()) {
            $_SESSION[':samlssp'] = array();

            $attrs = $this->samlauth->getAttributes();

	    $attrs = hook_ssp_manipulate_saml_atributes_before_mapping($this->config, $attrs);

            $fullname = $firstname = $lastname = $fullname = $phone =  $organization = null;

            if (empty($attrs)) {
                $username = SAMLSSPBase::getNameId();
                $email = $username;
            } else {
                $usernameMapping = $this->config->get('saml-ssp-attr-mapping-username');
                $mailMapping = $this->config->get('saml-ssp-attr-mapping-mail');
                $fullnameMapping = $this->config->get('saml-ssp-attr-mapping-fullname');
                $firstnameMapping = $this->config->get('saml-ssp-attr-mapping-firstname');
                $lastnameMapping = $this->config->get('saml-ssp-attr-mapping-lastname');
                $phoneMapping = $this->config->get('saml-ssp-attr-mapping-phone');

                if (!empty($usernameMapping) && isset($attrs[$usernameMapping]) && !empty($attrs[$usernameMapping][0])) {
                    $username = $attrs[$usernameMapping][0];
                }
                if (!empty($mailMapping) && isset($attrs[$mailMapping]) && !empty($attrs[$mailMapping][0])) {
                    $email = $attrs[$mailMapping][0];
                }
                if (!empty($fullnameMapping) && isset($attrs[$fullnameMapping]) && !empty($attrs[$fullnameMapping][0])) {
                    $fullname = $attrs[$fullnameMapping][0];
                }
                if (!empty($firstnameMapping) && isset($attrs[$firstnameMapping]) && !empty($attrs[$firstnameMapping][0])) {
                    $firstname = $attrs[$firstnameMapping][0];
                }
                if (!empty($lastnameMapping) && isset($attrs[$lastnameMapping]) && !empty($attrs[$lastnameMapping][0])) {
                    $lastname = $attrs[$lastnameMapping][0];
                }
                if (!empty($phoneMapping) && isset($attrs[$phoneMapping]) && !empty($attrs[$phoneMapping][0])) {
                    $phone = $attrs[$phoneMapping][0];
                }

                if (empty($fullname) && (!empty($firstname) || !empty($lastname))) {
                    $fullname = $firstname.' '.$lastname;
                }

                if (empty($firstname) && empty($lastname)) {
                    $data = explode(" ", $fullname, 2);
                    $firstname = $data[0];
                    if (isset($data[1])) {
                        $lastname = $data[1];
                    }
                }

                if ($processingStaff) {
                    $systemRoleMapping = $this->config->get('saml-ssp-attr-mapping-system-role');
                    $rolePrimaryMapping = $this->config->get('saml-ssp-attr-mapping-primary-role');
                    $roleSecondaryMapping = $this->config->get('saml-ssp-attr-mapping-secondary-role');
                    $departamentPrimaryMapping = $this->config->get('saml-ssp-attr-mapping-primary-departament');
                    $departamentSecondaryMapping = $this->config->get('saml-ssp-attr-mapping-secondary-departament');
		    $teamMapping = $this->config->get('saml-ssp-attr-mapping-teams');

                    if (!empty($systemRoleMapping) && isset($attrs[$systemRoleMapping]) && !empty($attrs[$systemRoleMapping][0])) {
                        $systemRole = $attrs[$systemRoleMapping][0];
                    }

                    $roles = array();
                    if (!empty($rolePrimaryMapping) && isset($attrs[$rolePrimaryMapping]) && !empty($attrs[$rolePrimaryMapping])) {
			$rolePrimary = $attrs[$rolePrimaryMapping];
                        if (count($rolePrimary) == 1) {
                            $rolePrimary = explode(",", $rolePrimary[0]);
                        }

                        $roles = $rolePrimary;
                        if (count($roles) < 2) {
                            if (!empty($roleSecondaryMapping) && isset($attrs[$roleSecondaryMapping]) && !empty($attrs[$roleSecondaryMapping][0])) {
                                $roles[] = $attrs[$roleSecondaryMapping][0];
                            }
                        }
                    }

                    $departaments = array();
                    if (!empty($departamentPrimaryMapping) && isset($attrs[$departamentPrimaryMapping]) && !empty($attrs[$departamentPrimaryMapping])) {
                        $departamentPrimary = $attrs[$departamentPrimaryMapping];
                        if (count($rolePrimary) == 1) {
                            $departamentPrimary = explode(",", $departamentPrimary[0]);
                        }

                        $departaments = $departamentPrimary;
                        if (count($departaments) < 2) {
                            if (!empty($departamentSecondaryMapping) && isset($attrs[$roleSecondaryMapping]) && !empty($attrs[$departamentSecondaryMapping][0])) {
                                $departaments[] = $attrs[$departamentSecondaryMapping][0];
                            }
                        }
                    }

                    $teams = array();
                    if (!empty($teamMapping) && isset($attrs[$teamMapping]) && !empty($attrs[$teamMapping])) {
                        $teams = $attrs[$teamMapping];
                        if (count($teams) == 1) {
                            $teams = explode(",", $teams[0]);
                        }
                    }
                } else {
                    $organizationMapping = $this->config->get('saml-ssp-attr-mapping-organization');

                    if (!empty($organizationMapping) && isset($attrs[$organizationMapping]) && !empty($attrs[$organizationMapping][0])) {
                        $organization = $attrs[$organizationMapping][0];
                    }
                }
            }

            if (!isset($username) || !isset($email)) {
                echo 'Username or email not provided. Veryify that the IdP is providing the expected values and that the attribute mapping is configured properly ';
                exit();
            }

            $_SESSION[':samlssp']['user'] = $username;
            $_SESSION[':samlssp']['email'] = $email;
            $_SESSION[':samlssp']['name'] = $fullname;
            $_SESSION[':samlssp']['phone'] = $phone;

            $_SESSION[':samlssp']['firstname'] = $firstname;
            $_SESSION[':samlssp']['lastname'] = $lastname;

            if ($processingStaff) {
                $_SESSION[':samlssp']['systemrole'] = $systemRole;
                $_SESSION[':samlssp']['roles'] = $roles;
                $_SESSION[':samlssp']['departaments'] = $departaments;
                $_SESSION[':samlssp']['teams'] = $teams;
            } else {
                $_SESSION[':samlssp']['organization'] = $organization;
            }
            
            $nameID = $this->samlauth->getAuthData('saml:sp:NameID');

            // SAML data
            $_SESSION[':samlssp']['bk'] = $_GET['bk'];
            $_SESSION[':samlssp']['nameid'] = null;
            if (!empty($nameID) && isset($nameID->value)) {
                $_SESSION[':samlssp']['nameid'] = $nameID->value;
            }

            if (isset($_REQUEST['RelayState']) && !empty($_REQUEST['RelayState'])) {
                $_SESSION[':samlssp']['relaystate'] = $_REQUEST['RelayState'];
            }

            hook_ssp_manipulate_attributes_from_saml_session_mapping($this->config, $attrs);

            if ($processingStaff) {
                Http::redirect(ROOT_PATH . 'scp/login.php');
            } else {
                Http::redirect(ROOT_PATH . 'login.php');
            }
        } else {
            $errorMsg = 'SAML authentication failed';
            if ($processingStaff) {
                $_SESSION['_staff']['auth']['msg'] = $errorMsg;
            } else {
                return new AccessDenied($errorMsg);
            }
        }
    }

    public static function isEnabled($config, $mode = 'samlssp') {
        $isEnabled = false;

        if (strcmp($mode, 'samlssp.staff') === 0) {
            $values = array('staff', 'all');
        } else {
            $values = array('client', 'all');
        }

        $samlModeConfig = $config->get('saml-ssp-mode');
        if (in_array($samlModeConfig, $values)) {
            $isEnabled = true;
        }
        return $isEnabled;
    }
}

class SAMLSSPStaffAuthBackend extends ExternalStaffAuthenticationBackend {
    public static $id = "samlssp.staff";
    public static $name = "SAML STAFF";

    public static $service_name = "SAML For Agent/Admin";

    protected $config;
    protected $samlbase;

    public function __construct($config) {
        $this->config = $config;
        $this->samlbase = new SAMLSSPBase($config);
        $this->samlbase->id = self::$id;

        $custom_service_name = $this->config->get('saml-ssp-customizations-agent-login-text');
        if (!empty($custom_service_name)) {
            self::$service_name = $custom_service_name;
        }
    }

    public function signOn() {
        if (!isset($_SESSION[':samlssp']) || !isset($_SESSION[':samlssp']['bk']) || strcmp($_SESSION[':samlssp']['bk'], 'samlssp.staff') !== 0) {
            return;
        }

        unset($_SESSION['_staff']['auth']['msg']);

        $autocreate = $this->config->get('saml-ssp-options-autocreate-staff');
        $updatestaff = $this->config->get('saml-ssp-options-update-staff');

        $account_matcher = $this->config->get('saml-ssp-options-account_matcher');
        $username = $this->samlbase->getUser();
        if (!preg_match('/^[\p{L}\d._-]+$/u', $username) && $this->config->get('saml-ssp-options-username-clean')) {
            $username = str_replace(array("@", " ", "^", "'", "\"", "$", "?", '¿', '¡', '!'), "_", $username);
        }
        $email = $this->samlbase->getEmail();

        if ($account_matcher == 'username') {
            $userfield = $username;
        } else {
            $userfield = $email;
        }

        $firstname = $this->samlbase->getFirstName();
        $lastname = $this->samlbase->getLastName();
        $phone = Format::phone($this->samlbase->getPhone());

        $depts = $this->samlbase->getDeptIdValues(true);
        $roles = $this->samlbase->getRoleIdValues(true);
        $teams = $this->samlbase->getTeamIdValues(true);

        $dept_id_1 = $role_id_1 = null;
        if (!empty($depts) && !empty(intval($depts[0]))) {
            $dept_id_1 = intval($depts[0]);
        }

        if (!empty($roles) && !empty(intval($roles[0]))) {
            $role_id_1 = intval($roles[0]);
        }

        $teamsData = array();
        $teamIdsWithAlert = $this->samlbase->getIdsOfTeamsWithAlertsEnabled();
        foreach ($teams as $key => $teamId) {
            if (!empty(intval($teamId))) {
                $teamsData[] = array(intval($teamId), intval(in_array($teamId, $teamIdsWithAlert)));
            }
        }

        $access = array();
        //$deptIdsWithAlert = $this->samlbase->getIdsOfDeptsWithAlertsEnabled();
        foreach ($depts as $key => $deptId) {
            if ($key == 0 || !isset($roles[$key])) {
                continue;
            }

            $roleId = $roles[$key];
            if (!empty(intval($deptId)) && !empty(intval($roleId))) {
                $access[] = array(intval($deptId), intval($roleId), null);
                //$access[] = array(intval($deptId), intval($roleId), in_array($deptId, $deptIdsWithAlert)? true: null);
            }
        }

        if (!empty($userfield)) {
            if ($account_matcher == 'username') {
                $staff_id = Staff::getIdByUsername($userfield);
            } else {
                $staff_id = Staff::getIdByEmail($userfield);
            }

            $staff = null;
            if ($staff_id) {
                $staff = StaffSession::lookup($staff_id);
            }
            if ($staff && $staff->getId()) {
                if (!$staff instanceof StaffSession) {
                    // osTicket <= v1.9.7 or so
                    $staff = new StaffSession($staff->getId());
                }

                if ($updatestaff) {
                    $changed = false;

                    // Update firstname
                    if (!empty($firstname) && $staff->getFirstName() != $firstname) {
                        $staff->firstname = $firstname;
                        $changed = true;
                    }

                    // Update lastname
                    if (!empty($lastname) && $staff->getLastName() != $lastname) {
                        $staff->lastname = $lastname;
                        $changed = true;
                    }

                    // Update mail
                    if ($account_matcher != 'mail' && !empty($email) && $staff->getEmail() != $email) {
                        if (Validator::is_email($email)) {
                            $staff->email = $email;
                            $changed = true;
                        }
                    }

                    // Update Phone
                    if (!empty($phone) && $staff->getVar("phone") != $phone) {
                        $staff->phone = $phone;
                        $changed = true;
                    }

                    // Update isAdmin
                    $isAdmin = $this->samlbase->getSystemRoleValue();
                    if ($isAdmin != null && $staff->isAdmin() != $isAdmin) {
                        $staff->isAdmin = $isAdmin;
                        $changed = true;
                    }

                    if ($changed) {
                        $staff->save();
                    }

                    // Update Dept1 // Role 1
                    if ($staff->dept_id != $dept_id_1 || $staff->role_id != $role_id_1) {
                        $staff->dept_id = $dept_id_1;
                        $staff->role_id = $role_id_1;
                        $staff->setDepartmentId($dept_id_1);
                        $staff->save();
                        /*
                        if ($da = $staff->dept_access->findFirst(array(
                            'dept_id' => $staff->getDeptId()))
                        ) {
                            $staff->dept_access->remove($da);
                        }

                        $da = StaffDeptAccess::create(array(
                            'dept_id' => $dept_id_1,
                            'role_id' => $this->role_id,
                        ));
                        $da->setAlerts(true);
                        $staff->dept_access->add($da);
                        */
                    }

                    // Update rest of Depts/Roles
                    $staff->updateAccess($access, $errors);

                    // Update Teams
                    $staff->updateTeams($teamsData, $errors);
                    // TODO Register errors while updating teams
                    // if (!empty($errors)) {
                    //
                    //}
                }

                $staff = hook_ssp_staff_post_updating($this, $staff, $staff_id);

                return $staff;
            } else {
                if ($autocreate) {
                    // Verify that username/email (the one not used to identify) does not exists
                    if ($account_matcher == 'username') {
                        $found = Staff::getIdByEmail($mail);
                        if ($found) {
                            $_SESSION['_staff']['auth']['msg'] = "The mail '".htmlentities($mail)."' already exists, can't provision '".htmlentities($userfield)."'";
                        }
                    } else {
                        $found = Staff::getIdByUsername($username);
                        if ($found) {
                            $_SESSION['_staff']['auth']['msg'] = "The username '".htmlentities($username)."' already exists, can't provision '".htmlentities($userfield)."'";
                        }
                    }

                    if (empty($found)) {
                        $staff_data = array(
                            'username' => $username,
                            'firstname' => $firstname,
                            'lastname' => $lastname,
                            'email' => $email,
                            'dept_id' => $dept_id_1,
                            'role_id' => $role_id_1,
                            'isactive' => 1,
                            'isadmin' => $this->samlbase->getSystemRoleValue(true),
                            'phone' => $phone,
                            'timezone' => $this->samlbase->getDefaultTimezone()
                        );

                        $staff_data = hook_ssp_staff_pre_jit($this, $staff_data);

                        $staff = Staff::create($staff_data, $errors);
                        $staff->save();

                        if (!empty($errors)) {
                            $extra_info = 'Empty/Invalid values: '.implode(",", array_keys($errors));
                            $_SESSION['_staff']['auth']['msg'] = "The user '".htmlentities($userfield)."' is not a staff member and provisioning failed.".$extra_info;
                        } else {
                            $defaultStaffPermission = array(
                                User::PERM_CREATE,
                                User::PERM_EDIT,
                                User::PERM_DELETE,
                                User::PERM_MANAGE,
                                User::PERM_DIRECTORY,
                                Organization::PERM_CREATE,
                                Organization::PERM_EDIT,
                                Organization::PERM_DELETE,
                                FAQ::PERM_MANAGE,
                                Email::PERM_BANLIST
                            );

                            if (!empty($depts)) {
                                $staff->updateAccess($access, $errors);
                                // TODO Register errors while updating access
                                // if (!empty($errors)) {
                                //
                                //}
                            }

                            if (!empty($teams)) {
                                $staff->updateTeams($teamsData, $errors);
                                // TODO Register errors while updating teams
                                // if (!empty($errors)) {
                                //
                                //}
                            }

                            $defaultStaffPermission = array(
                                User::PERM_CREATE,
                                User::PERM_EDIT,
                                User::PERM_DELETE,
                                User::PERM_MANAGE,
                                User::PERM_DIRECTORY,
                                Organization::PERM_CREATE,
                                Organization::PERM_EDIT,
                                Organization::PERM_DELETE,
                                FAQ::PERM_MANAGE,
                            );

                            $defaultStaffPermission = hook_ssp_manipulate_staff_default_permissions($this, $defaultStaffPermission);

                            $staff->updatePerms($defaultStaffPermission);

                            if ($staff->save()) {
                                $staff = hook_ssp_staff_post_jit($this, $staff_data, $staff);

                                $staff_id = $staff->getID();
                                if ($staff_id) {
                                    $staff2 = StaffSession::lookup($staff_id);
                                    return $staff2;
                                }
                            }
                            $_SESSION['_staff']['auth']['msg'] = "The user '".htmlentities($userfield)."' is not a staff member and sso failed after trying to provision it.";
                        }
                    }
                } else {
                    $_SESSION['_staff']['auth']['msg'] = "The user '".htmlentities($userfield)."' is not a staff member and provisioning is disabled";
                }
            }
        } else {
            $_SESSION['_staff']['auth']['msg'] = 'SAML authentication failed.'.'The '.$account_matcher.' could not be retrieved from the IdP, Review the Attribute Mapping section as well as the SAMLResponse sent by the IdP';
        }
    }

    public static function signOut($user) {
        if (!isset($_SESSION[':samlssp']) || !isset($_SESSION[':samlssp']['bk']) || strcmp($_SESSION[':samlssp']['bk'], 'samlssp.staff') !== 0) {
            return;
        }

        $pluginConfig = @new SAMLSSPAuthPlugin('SAMLSSPPluginConfig');
        $pluginConfig->config_class = 'SAMLSSPPluginConfig';
        $config = $pluginConfig->getConfig();
        $isLogoutEnabled = (bool) $config->get('saml-ssp-options-slo');
        if ($isLogoutEnabled) {
            SAMLSSPBase::samlLogout($config, 'samlssp.staff');
        }

        unset($_SESSION[':samlssp']);
        parent::signOut($user);
    }

    public function triggerAuth() {
        if (!isset($_GET['bk']) || strcmp($_GET['bk'], 'samlssp.staff') !== 0) {
            return;
        }

        if (SAMLSSPBase::isEnabled($this->config, 'samlssp.staff')) {
            $this->samlbase->triggerAuth();
        }
    }
}

class SAMLSSPClientAuthBackend extends ExternalUserAuthenticationBackend {

    public static $id = "samlssp";
    public static $name = "SAML";

    public static $service_name = "SAML For Clients";

    protected $config;
    protected $samlbase;

    public function __construct($config) {
        $this->config = $config;
        $this->samlbase = new SAMLSSPBase($config);
        $this->samlbase->id = self::$id;

        $custom_service_name = $this->config->get('saml-ssp-customizations-client-login-text');
        if (!empty($custom_service_name)) {
            self::$service_name = $custom_service_name;
        }
    }

    public function supportsInteractiveAuthentication() {
        return false;
    }

    public function retrieveUser($userfield, $account_matcher) {
        $user = null;

        if ($account_matcher == 'username') {
            $acct = UserAccount::lookup(array('username' => $userfield));
        } else {
            $user = User::lookup(array('emails__address' => $userfield));
            if ($user) {
                $acct = $user->getAccount();
            }
        }

        if (!empty($acct) && !empty($acct->getId())) {
            if (empty($user)) {
                $user = $acct->getUser();
            }
        }

        return $user;
    }

    public function signOn() {
        if (!isset($_SESSION[':samlssp']) || !isset($_SESSION[':samlssp']['bk']) || strcmp($_SESSION[':samlssp']['bk'], 'samlssp') !== 0) {
            return;
        }

        $autocreate = $this->config->get('saml-ssp-options-autocreate');
        $updateuser = $this->config->get('saml-ssp-options-updateuser');
        $account_matcher = $this->config->get('saml-ssp-options-account_matcher');

        $username = $this->samlbase->getUser();
        if (!preg_match('/^[\p{L}\d._-]+$/u', $username) && $this->config->get('saml-ssp-options-username-clean')) {
            $username = str_replace(array("@", " ", "^", "'", "\"", "$", "?", '¿', '¡', '!'), "_", $username);
        }
        $email = $this->samlbase->getEmail();

        if ($account_matcher == 'username') {
            $userfield = $username;
        } else {
            $userfield = $email;
        }

        $user = null;
        if (!empty($userfield)) {
            $user = $this->retrieveUser($userfield, $account_matcher);
            
            if (!empty($user)) {
                if ($updateuser) {
                    $changed = false;

                    // Update name
                    if (!empty($this->samlbase->getFullName()) && $user->name != $this->samlbase->getFullName()) {
                        $user->name = $this->samlbase->getFullName();
                        $changed = true;
                    }
                    // Update mail
                    if ($account_matcher != 'mail' && !empty($email) && $user->getEmail() != $email) {
                        if (Validator::is_email($email) && !User::lookup(array('emails__address' => $email))) {
                            $user->default_email->address = $email;
                            $user->default_email->save();
                            $changed = true;
                        }
                    }

                    // Update Phone
                    if (!empty($this->samlbase->getPhone()) && $user->getPhoneNumber() != $this->samlbase->getPhone()) {
                        foreach ($user->getDynamicData() as $e) {
                            if ($phone = $e->getAnswer('phone')) {
                                $phone->value = Format::phone($this->samlbase->getPhone());
                                $phone->save();
                                $changed = true;
                            }
                        }
                    }

                    // Update Organization
                    $user_org = $user->getOrganization();
                    $user_org_name = '';
                    if ($org) {
                        $user_org_name = $user_org->name;
                    }

                    $orgNameValue = $this->samlbase->getOrganizationNameValue();
                    if (!empty($orgNameValue) && $user_org_name != $orgNameValue) {
                        $org = Organization::lookup(array('name' => $orgNameValue));
                        if (!$org) {
                            $org = Organization::create(array(
                                'name' => $orgNameValue,
                                'created' => new SqlFunction('NOW'),
                                'updated' => new SqlFunction('NOW'),
                            ));
                            $org->save(true);
                        }
                        $user->setOrganization($org);
                        $changed = true;
                    }

                    if ($changed) {
                        $user->save();
                    }
                }

                $user = hook_ssp_client_post_updating($this, $user);
                $endUser = new EndUser($user);
                $client = new ClientSession($endUser);
                $this->setRedirectOnSession();
                return $client;
            } else {
                if ($autocreate) {
                    // Verify that username/email (the one not used to identify) does not exists
                    if ($account_matcher == 'username') {
                        $found = User::lookup(array('emails__address' => $email));
                        if (isset($found)) {
                            return new AccessDenied("The email '".htmlentities($email)."' already exists and this field must be unique, can't provision client '".htmlentities($userfield))."'";
                        }
                    } else {
                        $found = UserAccount::lookup(array('username' => $username));
                        if (isset($found)) {
                            return new AccessDenied("The username '".htmlentities($username)."' already exists and this field must be unique, can't provision client '".htmlentities($userfield))."'";
                        }
                    }

                    try {
                        hook_ssp_client_pre_jit($this);

                        $clientreq = new ClientCreateRequest($this, $username, $this->samlbase->getProfile());
                        $result = $clientreq->attemptAutoRegister();
                        if ($result instanceof ClientSession) {
                            $orgNameValue = $this->samlbase->getOrganizationNameValue(true);
                            $orgNameValue = null;
                            if (empty($orgNameValue)) {
                                $this->setRedirectOnSession();

                                $result = hook_ssp_client_post_jit($this, $result);
                                return $result;
                            } else {
                                $acct = $result->getAccount();
                                $user = $acct->getUser();

                                $org = Organization::lookup(array('name' => $orgNameValue));
                                if (!$org) {
                                    $org = Organization::create(array(
                                        'name' => $orgNameValue,
                                        'created' => new SqlFunction('NOW'),
                                        'updated' => new SqlFunction('NOW'),
                                    ));
                                    $org->save(true);
                                }
                                $user->setOrganization($org);
                                $user->save();
                                $endUser = new EndUser($user);
                                $client = new ClientSession($endUser);
                                $this->setRedirectOnSession();

                                $client = hook_ssp_client_post_jit($this, $client);
                                return $client;
                            }
                        } else if (!empty($_POST)) {
                            return new AccessDenied("The client '".htmlentities($userfield)."' does not exists and Just-In-Time provisioning failed");
                        } else {
                            if (!isset($user)) {
                                $user = $this->retrieveUser($userfield, $account_matcher);
                            }

                            $endUser = new EndUser($user);
                            $client = new ClientSession($endUser);
                            $this->setRedirectOnSession();

                            $client = hook_ssp_client_post_jit_error($this, $client);
                            return $client;
                        }
                    } catch (Exception $e) {
                        $errorMsg = "The client '".htmlentities($userfield)."' does not exists and Just-In-Time provisioning failed.";
                        if (!empty($e->getMessage())) {
                            $errorMsg .= $e->getMessage();
                        } else {
                            if ($account_matcher == 'username') {
                                $errorMsg .= "A possible reason is that the mail ". htmlentities($email) ." can be already registered";
                            } else {
                                $errorMsg .= "A possible reason is that the username ". htmlentities($username) ." can be already registered";
                            }
                        }
                        return new AccessDenied($errorMsg);
                    }
                } else if (!empty($_POST)) {
                    return new AccessDenied("The client '".htmlentities($userfield)."' does not exists and Just-In-Time provisioning is disabled");
                }
            }
        } else if (!empty($_POST)) {
            return new AccessDenied('SAML authentication failed.'.'The '.htmlentities($account_matcher).' could not be retrieved from the IdP, Review the Attribute Mapping section as well as the SAMLResponse sent by the IdP');
        }
    }

    public static function signOut($user) {
        if (!isset($_SESSION[':samlssp']) || !isset($_SESSION[':samlssp']['bk']) || strcmp($_SESSION[':samlssp']['bk'], 'samlssp') !== 0) {
            return;
        }

        $pluginConfig = @new SAMLSSPAuthPlugin('SAMLSSPPluginConfig');
        $pluginConfig->config_class = 'SAMLSSPPluginConfig';
        $config = $pluginConfig->getConfig();
        $isLogoutEnabled = (bool) $config->get('saml-ssp-options-slo');
        if ($isLogoutEnabled) {
            SAMLSSPBase::samlLogout($config, 'samlssp');
        }

        unset($_SESSION[':samlssp']);
        parent::signOut($user);
    }

    public function triggerAuth() {
        if (SAMLSSPBase::isEnabled($this->config, "samlssp")) {
            $this->samlbase->triggerAuth();
        }
    }

    public function setRedirectOnSession() {
        $relayState = $this->samlbase->getRelayState();
        if (!empty($relayState)) {
            print_r($relayState);exit();
            $this->samlbase->removeRelayState();
            $_SESSION['_client']['auth']['dest'] = $relayState;
        }
    }
}
