<?php

/*
   In order to retrieve $config from $samlsspStaffAuthBackend or $samlsspClientAuthBackend,
   access $samlsspStaffAuthBackend->config or $samlsspClientAuthBackend->config

   In order to retrieve SAMLBase object to be able retrieve user info from $samlsspStaffAuthBackend or
   $samlsspClientAuthBackend, access $samlsspStaffAuthBackend->samlbase or $samlsspClientAuthBackend->samlbase

*/

////////////////////
// SAMLBase Hooks //
////////////////////

function hook_ssp_manipulate_saml_atributes_before_mapping($config, $attrs) {
    $principal = $attrs['urn:oid:1.3.6.1.4.1.5923.1.1.1.6'];
    $entitlementURNs = $attrs['urn:oid:1.3.6.1.4.1.5923.1.1.1.7'];
    if(empty($entitlementURNs)){
        syslog(LOG_NOTICE,"User with principal '".$principal."' logged in, but does not have any entitlements on object");
        access_error();
        exit();
    }

    //User primary department is set to be the department with department ID 1
    $attrs['department'] = array(1);

    //Set user email using the email attribute
    $mailAttr = $config->get('saml-ssp-attr-mapping-mail');
    $samlMails = $attrs[$mailAttr];
    if($samlMails == NULL || empty($samlMails)){
	syslog(LOG_ERROR,"User with principal '".$principal."' logged in successfully, but does not have any emails on object");
	access_error();
	exit();
    }else if(is_array($samlMails)){
	$attrs[$mailAttr] = array($samlMails[0]);
    }else{
	$attrs[$mailAttr] = array($samlMails);
    }

    //Set user primary role from the entitlement attribute
    $attrs['role'] = array();
    foreach($entitlementURNs as $entitlementURN){
	if(str_starts_with($entitlementURN,'urn:mace:gunet.gr:ediplomas.gr:helpdesk')){
            $entitlementFields = explode(":",$entitlementURN);
            $rights = $entitlementFields[6];

	    $roleQuery = "SELECT id FROM ".ROLE_TABLE." WHERE name LIKE '".$rights."'";
	    $roleQueryRes = db_result(db_query($roleQuery));
            if($roleQueryRes == NULL){
                syslog(LOG_ERR,"Faulty rights on entitlement '".$entitlementURN."'");
                access_error();
                exit();
	    }
	    array_push($attrs['role'],$roleQueryRes);
	}
    }

    return $attrs;
}

function hook_ssp_manipulate_attributes_from_saml_session_mapping($config, $attrs) {
    // Add here code to manipalate the $_SESSION[':saml'] dict

}

// In order to retrieve $config from $samlsspStaffAuthBackend or $samlsspClientAuthBackend,
// access $samlsspStaffAuthBackend->config or $samlsspClientAuthBackend->config
// 
// In order to retrieve SAMLBase object to be able retrieve user info from $samlsspStaffAuthBackend or
// $samlsspClientAuthBackend, access $samlsspStaffAuthBackend->samlbase or $samlsspClientAuthBackend->samlbase


////////////////////////////////
// SAMLStaffAuthBackend Hooks //
////////////////////////////////

function hook_ssp_staff_post_updating($samlsspStaffAuthBackend, $staff, $staff_id) {
    // Add here code to manipulate staff_data in some way

    return $staff;
}

function hook_ssp_staff_pre_jit($samlsspStaffAuthBackend, $staff_data) {
    // Add here code to manipulate staff_data in some way
    
    return $staff_data;
}

function hook_ssp_manipulate_staff_default_permissions($samlsspStaffAuthBackend, $defaultStaffPermission) {
    // Add here code to maniulate 

    return $defaultStaffPermission;
}

function hook_ssp_staff_post_jit($samlsspStaffAuthBackend, $staff_data, $staff) {
    // Add here code to manipulate $staff object or link objects to it

    return $staff;
}


////////////////////////////////////
// SAMLSSPClientAuthBackend Hooks //
////////////////////////////////////

function hook_ssp_client_post_updating($samlsspClientAuthBackend, $user) {
    // Add here code to manipulate $user object or link objects to it
    
    return $user;
}

function hook_ssp_client_pre_jit($samlsspClientAuthBackend) {
    // Add here code and execute it before the client pre jit
    
}

function hook_ssp_client_post_jit($samlsspClientAuthBackend, $clientSession) {
    // Add here code to manipulate $user object or link objects to it
    // $user = $result->getAccount()->getUser();
    // $clientSession = new ClientSession(new EndUser($user));

    return $clientSession;
}

function hook_ssp_client_post_jit_error($samlsspClientAuthBackend, $clientSession) {
    // Maybe raise an AccessDenied on this scenario with
    // new AccessDenied($errorMsg);
    // $clientSession = new AccessDenied("Client JIT ERROR");

    return $clientSession;
}
