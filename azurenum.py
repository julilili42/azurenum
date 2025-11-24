#!/usr/bin/env python3

import json
import sys
import argparse
import requests
import msal
import platform
import ctypes
from datetime import datetime, timedelta
import config as cfg
from config import AuthFlow
from report import Reporter
from authentication import AuthManager, Resource, AuthError
from api import MSGraphClient, MSGraphBetaClient
import os

RED, GREEN, YELLOW, CYAN, ORANGE, NC = (
    cfg.RED, cfg.GREEN, cfg.YELLOW, cfg.CYAN, cfg.ORANGE, cfg.NC
)


def unset_colors():
    global RED, GREEN, YELLOW, CYAN, ORANGE, NC
    RED = GREEN = YELLOW = CYAN = ORANGE = NC = ""


if platform.system() == 'Windows':
    IS_WINDOWS = True
else:
    IS_WINDOWS = False

args = None
rep = None
json_content = {"findings": []}

# Start global session for msal and python-requests
# Need to patch the prepare_request method to remove the x-client-os header that msal sets


class PatchedSession(requests.Session):
    def prepare_request(self, request, *args, **kwargs):
        # Call the parent class's prepare_request method
        request = super().prepare_request(request, *args, **kwargs)

        # Remove the unwanted header if it exists
        if "x-client-os" in request.headers:
            del request.headers["x-client-os"]

        return request


session = PatchedSession()
session.headers.update({"User-Agent": cfg.DEFAULT_USER_AGENT})


def get_msgraph(endpoint, params, token, version="v1.0"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = cfg.MS_GRAPH_API + "/" + version + endpoint
    r = requests.get(url, params=params, headers=headers)
    result = json.loads(r.text)

    # Check request worked
    if "@odata.context" not in result:
        rep.error(f"Could not fetch URL: {r.url}")
        print(result)
        return

    return result


def get_msgraph_value(endpoint, params, token, version="v1.0"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = cfg.MS_GRAPH_API + "/" + version + endpoint
    results = []
    while True:
        r = requests.get(url, params=params, headers=headers)
        rawResult = json.loads(r.text)

        # Check request worked
        if "@odata.context" not in rawResult:
            rep.error(f"Could not fetch URL: {r.url}")
            print(rawResult)
            return

        # Add results
        results.extend(rawResult["value"])

        # If no nextLink present, break and return
        if "@odata.nextLink" not in rawResult:
            break
        else:
            url = rawResult["@odata.nextLink"]
            params = {}  # nextLink includes the search params

    return results


def get_aadgraph(endpoint, params, tenantId, token, apiVersion="1.61-internal"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = f"{cfg.AAD_GRAPH_API}/{tenantId}{endpoint}"
    params["api-version"] = apiVersion
    r = requests.get(url, params=params, headers=headers)
    result = json.loads(r.text)

    # Check request worked
    if "odata.metadata" not in result:
        rep.error(f"Could not fetch URL: {r.url}")
        print(result)
        return

    return result


def get_aadgraph_value(endpoint, params, tenantId, token, apiVersion="1.61-internal"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = f"{cfg.AAD_GRAPH_API}/{tenantId}{endpoint}"
    results = []
    params["api-version"] = apiVersion
    while True:
        r = requests.get(url, params=params, headers=headers)
        rawResult = json.loads(r.text)

        # Check request worked
        if "odata.metadata" not in rawResult:
            rep.error(f"Could not fetch URL: {r.url}")
            print(rawResult)
            return

        # Add results
        results.extend(rawResult["value"])

        # If no nextLink present, break and return
        if "odata.nextLink" not in rawResult:
            break
        else:
            nextLink = rawResult["odata.nextLink"]
            url = f"{cfg.AAD_GRAPH_API}/{tenantId}/{nextLink}&api-version={apiVersion}"
            params = {}  # nextLink includes the search params

    return results


def get_arm(endpoint, params, token, apiVersion="2018-02-01"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = cfg.ARM_API + endpoint
    params["api-version"] = apiVersion
    r = requests.get(url, params=params, headers=headers)
    result = json.loads(r.text)

    if "value" not in result:
        rep.error(f"Could not fetch URL: {r.url}")
        print(result)
        return

    return result


def basic_info(org, groups, servicePrincipals, groupSettings, users, userRegistrationDetails, msGraphToken, msGraphTokenForAzCli, armToken):

    tenantId = org["id"]
    # Object quota
    objNum = org["directorySizeQuota"]["used"]
    objLimit = org["directorySizeQuota"]["total"]
    displayName = org["displayName"]
    onPremisesSyncEnabled = org["onPremisesSyncEnabled"]
    if onPremisesSyncEnabled is None:
        onPremisesSyncEnabled = "Disabled"
    else:
        onPremisesSyncEnabled = "Enabled"

    # Licenses
    aadLicenses = [plan["servicePlanId"] for plan in org["assignedPlans"]
                   if plan["capabilityStatus"] == "Enabled" and plan["service"] == "AADPremiumService"]
    if cfg.AAD_PREMIUM_P2 in aadLicenses:
        aadPlan = "Microsoft Entra ID P2"
    elif cfg.AAD_PREMIUM_P1 in aadLicenses:
        aadPlan = "Microsoft Entra ID P1"
    else:
        aadPlan = "Microsoft Entra ID Free"

    if users != None:
        userNum = len(users)
        guestNum = len([user for user in users if user["userType"] == "Guest"])
        guestPercent = round(guestNum / userNum * 100, 2)
        pendingInvitations = get_msgraph_value(
            "/users/",
            {
                "$select": "userPrincipalName,externalUserState,createdDateTime",
                "$filter": "externalUserState eq 'PendingAcceptance'"
            },
            msGraphToken
        )
        pendingInvitationsNum = len(pendingInvitations)
        # Calculate # of orphaned Accounts
        current_datetime = datetime.utcnow()  # get the current datetime in UTC timezone
        invitationsSinceLarger90 = 0
        invitationsSinceLarger180 = 0
        invitationsSinceLarger365 = 0
        for invitation in pendingInvitations:
            # format '2023-04-25T07:36:44Z'
            date_string = invitation["createdDateTime"]
            # convert the input string to a datetime object
            given_datetime = datetime.fromisoformat(date_string[:-1])
            # calculate the number of days between the given datetime and the current datetime
            days_since = (current_datetime - given_datetime).days
            if days_since > 365:
                invitationsSinceLarger365 += 1
                invitationsSinceLarger180 += 1
                invitationsSinceLarger90 += 1
                continue
            if days_since > 180:
                invitationsSinceLarger180 += 1
                invitationsSinceLarger90 += 1
                continue
            if days_since > 90:
                invitationsSinceLarger90 += 1
        # Calculate guests with no signin since a long time
        noSignInLarger90 = 0
        noSignInLarger180 = 0
        noSignInLarger365 = 0
        acceptedGuests = get_msgraph_value(
            "/users/",
            {
                "$select": "userPrincipalName,externalUserState,signInActivity",
                "$filter": "externalUserState eq 'Accepted'"
            },
            msGraphTokenForAzCli
        )

        if acceptedGuests != None:  # If no global admin rights, the query will likely fail
            for guest in acceptedGuests:
                if "signInActivity" not in guest:
                    # TODO: this guest has never logged in, check creation date and maybe report it
                    continue
                # format '2023-04-25T07:36:44Z'
                interactive_date_string = guest["signInActivity"]["lastSignInDateTime"]
                if interactive_date_string != None:
                    interactive_given_datetime = datetime.fromisoformat(
                        interactive_date_string[:-1])  # convert the input string to a datetime object
                    # calculate the number of days between the given datetime and the current datetime
                    interactive_days_since = (
                        current_datetime - interactive_given_datetime).days
                else:
                    interactive_days_since = 0  # Never logged in interactively?
                # format '2023-04-25T07:36:44Z'
                non_interactive_date_string = guest["signInActivity"]["lastNonInteractiveSignInDateTime"]
                if non_interactive_date_string != None:
                    non_interactive_given_datetime = datetime.fromisoformat(
                        non_interactive_date_string[:-1])  # convert the input string to a datetime object
                    # calculate the number of days between the given datetime and the current datetime
                    non_interactive_days_since = (
                        current_datetime - non_interactive_given_datetime).days
                else:
                    non_interactive_days_since = 0  # Never logged in non-interactively?
                days_since_last_interaction = max(
                    interactive_days_since, non_interactive_days_since)
                if days_since_last_interaction > 365:
                    noSignInLarger365 += 1
                    noSignInLarger180 += 1
                    noSignInLarger90 += 1
                    continue
                if days_since_last_interaction > 180:
                    noSignInLarger180 += 1
                    noSignInLarger90 += 1
                    continue
                if days_since_last_interaction > 90:
                    noSignInLarger90 += 1
    if groups != None:
        groupNum = len(groups)
        # These are m365 groups that get created in public teams, should be modifiable (add memberships)
        modifiableGroups = [group for group in groups if group["visibility"]
                            == "Public" and group["membershipRule"] is None]
        modifiableGroupsNum = len(modifiableGroups)
    if servicePrincipals != None:
        nativeServicePrincipals = [
            spn for spn in servicePrincipals if spn["appOwnerOrganizationId"] == tenantId]
        nativeServicePrincipalsNum = len(nativeServicePrincipals)
        servicePrincipalNum = len(servicePrincipals)

    appRegistrations = get_msgraph_value("/applications", {}, msGraphToken)
    if appRegistrations == None:
        rep.error("Could not fetch App Registrations")

    subscriptionsRaw = get_arm("/subscriptions", {}, armToken)
    if subscriptionsRaw == None:
        rep.error("Could not fetch subscriptions")
    else:
        subscriptions = subscriptionsRaw["value"]

    # MFA Methods per User
    if userRegistrationDetails != None:
        usersWithoutMfa = [
            userRegistrationDetail for userRegistrationDetail in userRegistrationDetails if not userRegistrationDetail["isMfaCapable"]]
        usersWithoutMfaNum = len(usersWithoutMfa)
        mfaPercent = round(usersWithoutMfaNum / userNum * 100, 2)

    rep.header("Basic information")

    rep.info(f"TenantID: {tenantId}")
    rep.info(f"License: {aadPlan}")
    rep.info(f"Size quota: {objNum}/{objLimit}")
    rep.info(f"Display name: {displayName}")
    rep.info(f"On Premises Sync: {onPremisesSyncEnabled}")
    if users != None:
        rep.info(f"Users: {userNum}")
        rep.info(f"Guest Users: {guestNum}/{userNum} ({guestPercent} %)")
        rep.info(f"Pending invitations: {pendingInvitationsNum}")
        if invitationsSinceLarger90 > 0:
            rep.low(
                f"Pending invitations waiting for more than 90 days: {invitationsSinceLarger90}")
        if invitationsSinceLarger180 > 0:
            rep.low(
                f"Pending invitations waiting for more than 180 days: {invitationsSinceLarger180}")
        if invitationsSinceLarger365 > 0:
            rep.low(
                f"Pending invitations waiting for more than 365 days: {invitationsSinceLarger365}")
        if acceptedGuests != None:
            if noSignInLarger90 > 0:
                rep.low(
                    f"Guests with no signin for more than 90 days: {noSignInLarger90}")
            if noSignInLarger180 > 0:
                rep.low(
                    f"Guests with no signin for more than 180 days: {noSignInLarger180}")
            if noSignInLarger365 > 0:
                rep.low(
                    f"Guests with no signin for more than 365 days: {noSignInLarger365}")
    if userRegistrationDetails != None:
        rep.info(
            f"Users with no MFA methods: {usersWithoutMfaNum}/{userNum} ({mfaPercent} %)")
    if groups != None:
        rep.info(f"Groups: {groupNum}")
        rep.info(
            f"Modifiable groups: {modifiableGroupsNum} (Get them with `az ad group list | jq '.[] | select(.visibility == \"Public\") | select(.membershipRule == null).displayName'`)")
    if servicePrincipals != None:
        rep.info(
            f"Service Principals: {servicePrincipalNum} (aka. \"Enterprise applications\")")
        rep.info(
            f"Service Principals with AppRegs in this tenant: {nativeServicePrincipalsNum}")
    if appRegistrations != None:
        rep.info(
            f"Application Definitions: {len(appRegistrations)} (aka. \"App registrations\")")
    if subscriptionsRaw != None:
        rep.info(f"Subscriptions: {len(subscriptions)}")
        for subscription in subscriptions:
            subName = subscription["displayName"]
            rep.raw(f"- {subName}")
    rep.raw("")

    # LockoutPolicy
    if groupSettings != None:
        passwdRuleSettings = next(
            (setting for setting in groupSettings if setting["displayName"] == "Password Rule Settings"), None)
        lockoutDurationSeconds = 60  # default
        lockoutThreshold = 10  # default
        if passwdRuleSettings != None:
            lockoutDurationSeconds = next(
                (val["value"] for val in passwdRuleSettings["values"] if val["name"] == "LockoutDurationInSeconds"), None)
            lockoutThreshold = next(
                (val["value"] for val in passwdRuleSettings["values"] if val["name"] == "LockoutThreshold"), None)
        rep.info(f"Lockout Threshold: {lockoutThreshold}")
        rep.info(f"Lockout Duration Seconds: {lockoutDurationSeconds}")
        rep.raw("")

    # Security Defaults
    # Following command should get them
    # az rest --method get --url "{MS_GRAPH_API}/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    # also here: https://main.iam.ad.ext.azure.com/api/SecurityDefaults/GetSecurityDefaultStatus
    rep.info(
        f"Check if \"Security Defaults\" are enabled: {cfg.AZURE_PORTAL}/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Properties")


def enum_user_settings(authPolicy, groupSettings):
    rep.header("General user settings")

    # App Consent Policy
    if authPolicy != None:
        # https://portal.azure.com/?feature.msaljs=false#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings
        grantPolicies = authPolicy["permissionGrantPolicyIdsAssignedToDefaultUserRole"]

        rep.link(
            f"Portal: {cfg.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings")
        if "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" in grantPolicies:
            rep.med("Allow user consent for apps")
        elif "ManagePermissionGrantsForSelf.microsoft-user-default-low" in grantPolicies:
            rep.low(
                "Allow user consent for apps from verified publishers, for selected permissions")
        else:
            rep.info("Do not allow user consent")

    # App consent group settings
    if groupSettings != None:
        consentPolicySettings = next(
            (setting for setting in groupSettings if setting["displayName"] == "Consent Policy Settings"), None)
        # default, https://portal.azure.com/?feature.msaljs=false#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings
        enableAdminConsentRequests = "false"
        # blockUserConsentForRiskyApps = "false" # ??
        if consentPolicySettings != None:
            enableAdminConsentRequests = next(
                (val["value"] for val in consentPolicySettings["values"] if val["name"] == "EnableAdminConsentRequests"), None)
            # blockUserConsentForRiskyApps = consentPolicySettings["BlockUserConsentForRiskyApps"] ??
        rep.link(
            f"Portal: {cfg.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings")
        # rep.info(f"Block user consent for risky apps: {blockUserConsentForRiskyApps}")
        rep.info(
            f"Users can request admin consent to apps they are unable to consent to: {enableAdminConsentRequests}\n")

    if authPolicy != None:
        allowInvitesFrom = authPolicy["allowInvitesFrom"]
        guestUserRole = authPolicy["guestUserRoleId"]
        userCanReadOtherUsers = authPolicy["defaultUserRolePermissions"]["allowedToReadOtherUsers"]

        # Some security settings are just not visible in the Portal, they can be read/set over the Graph API though
        rep.link("Portal: NOT visible in the Portal!")
        if userCanReadOtherUsers == True:
            rep.info(
                "Users can read other users information (You can actually block this with the Graph API!)")
        else:
            rep.info("Users can not read other users information")
        rep.raw("")

        rep.link(
            f"Portal: {cfg.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings")
        # create apps
        allowCreateApps = authPolicy["defaultUserRolePermissions"]["allowedToCreateApps"]
        if allowCreateApps == True:
            rep.low(f"Users can register applications")
        else:
            rep.info(f"Users can not register applications")
        # create tenants
        allowCreateTenants = authPolicy["defaultUserRolePermissions"]["allowedToCreateTenants"]
        if allowCreateTenants == True:
            rep.low(f"Users can create tenants")
        else:
            rep.info(f"Users can not create tenants")

        rep.raw("")
        rep.link(
            f"Portal: {cfg.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/AllowlistPolicyBlade")
        # Invitation Policy setting
        if allowInvitesFrom == "adminsGuestInvitersAndAllMembers":
            rep.low("Member users and users assigned to specific admin roles can invite guest users including guests with member permissions")
        elif allowInvitesFrom == "everyone":  # default
            rep.med(
                "Anyone in the organization can invite guest users including guests and non-admins (most inclusive)")
        elif allowInvitesFrom == "adminsAndGuestInviters":
            rep.info(
                "Only users assigned to specific admin roles can invite guest users")
        elif allowInvitesFrom == "none":
            rep.info(
                "No one in the organization can invite guest users including admins (most restrictive)")
        else:
            rep.error(f"Unknown Guest Invite Policy: {allowInvitesFrom}")

        # Guest User permissions
        if guestUserRole == cfg.GUEST_ROLE_USER:
            rep.med("Guest users have the same access as members (most inclusive)")
        elif guestUserRole == cfg.GUEST_ROLE_GUEST:
            rep.low(
                "Guest users have limited access to properties and memberships of directory objects")
        elif guestUserRole == cfg.GUEST_ROLE_RESTRICTED:
            rep.info(
                "Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)")
        else:
            rep.error(f"Unknown Guest Role ID: {guestUserRole}")

    # Group Creation settings
    if groupSettings != None:
        groupUnifiedSettings = next(
            (setting for setting in groupSettings if setting["templateId"] == cfg.GROUP_UNIFIED_TEMPLATE_ID), None)
        # default, https://portal.azure.com/?feature.msaljs=false#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General
        enableAdGroupCreation = True
        if groupUnifiedSettings != None:
            enableAdGroupCreation = next(
                (val["value"] for val in groupUnifiedSettings["values"] if val["name"] == "EnableGroupCreation"), None)
        # https://portal.azure.com/?feature.msaljs=false#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General
        allowedToCreateSecurityGroups = authPolicy["defaultUserRolePermissions"]["allowedToCreateSecurityGroups"]
        rep.raw("")
        rep.link(
            f"Portal: {cfg.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General")
        # create AD groups
        if enableAdGroupCreation == True:
            rep.low("Users can create m365 groups")
        else:
            rep.info("Users can not create m365 groups")
        # create AD security groups
        if allowedToCreateSecurityGroups == True:
            rep.low(f"Users can create security groups\n")
        else:
            rep.info(f"Users can not create security groups\n")


def enum_device_settings(authPolicy, tenantId, aadGraphToken):
    rep.header("Device Settings")
    rep.link(
        f"Portal: {cfg.AZURE_PORTAL}/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings/menuId~/null")
    rep.info("If \"Users may join devices to Azure AD\" is enabled you may be able to create BPRT users, bypass the device quota, and provoke DoS: https://aadinternals.com/post/bprt/")

    # Bitlocker keys policy
    if authPolicy != None:
        allowReadBitlocker = authPolicy["defaultUserRolePermissions"]["allowedToReadBitlockerKeysForOwnedDevice"]
        if allowReadBitlocker == True:
            rep.med("Users can recover Bitlocker Keys of owned devices")
        else:
            rep.info("Users can not recover Bitlocker Keys of owned devices")

    # I wonder if using FOCI clients I can get this endpoint? "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy"

    # Registration quota, note that if device join/registration is disabled, this becomes irrelevant
    deviceConfiguration = get_aadgraph_value(
        "/deviceConfiguration", {}, tenantId, aadGraphToken)
    if deviceConfiguration is not None and len(deviceConfiguration) > 0:
        reg_quota = deviceConfiguration[0]["registrationQuota"]
        rep.info(f"Maximum number of devices per user: {reg_quota}")


def enum_admin_roles(msGraphToken, userRegistrationDetails):
    rep.header("Administrative Roles")

    directoryRoles = get_msgraph_value(
        "/directoryRoles", {"$expand": "members"}, msGraphToken)
    if directoryRoles == None:
        rep.error(f"Could not fetch administrative roles")
        return
    for directoryRole in directoryRoles:
        memberCount = len(directoryRole["members"])
        if memberCount == 0:
            continue
        roleName = directoryRole["displayName"]
        principalsInRole = directoryRole["members"]
        rep.info(f"{roleName}: {len(principalsInRole)}")
        for principal in principalsInRole:
            displayName = principal["displayName"]
            if principal["@odata.type"] == "#microsoft.graph.group":
                synced = "{ORANGE}(synced!){NC}" if principal["onPremisesSyncEnabled"] else ""
                rep.raw(f"- [GROUP] ({displayName}) {synced}")
            elif principal["@odata.type"] == "#microsoft.graph.user":
                userPrincipalName = principal["userPrincipalName"]
                userHasMfa = hasUserMFA(
                    userPrincipalName, userRegistrationDetails)
                lacksMfa = "" if userHasMfa else f" {ORANGE}(No MFA Methods!){NC}"
                if userHasMfa == None:
                    lacksMfa = " (MFA unknown)"
                synced = f" {ORANGE}(synced!){NC}" if principal["onPremisesSyncEnabled"] else ""
                rep.raw(
                    f"- [USER] {userPrincipalName} ({displayName}){synced}{lacksMfa}")
            elif principal["@odata.type"] == "#microsoft.graph.servicePrincipal":
                rep.raw(f"- [SERVICE] ({displayName})")
            else:
                principalType = principal["@odata.type"]
                rep.error(f"Unknown principal type: {principalType}")


def hasUserMFA(userPrincipalName, userRegistrationDetails):
    if userRegistrationDetails == None:
        # Information on MFA could not be fetched
        return None  # unknown whether MFA methods are set

    # pick user mfa methods
    registrationDetail = next(
        (registrationDetail for registrationDetail in userRegistrationDetails if registrationDetail["userPrincipalName"] == userPrincipalName), None)

    if registrationDetail == None:
        rep.error(f"User not found: {userPrincipalName}")
        return None

    return registrationDetail["isMfaCapable"]


def enum_pim_assignments(users, pimAccessToken, userRegistrationDetails):
    rep.header("PIM Assignments")

    eligibleAssignments = get_msgraph_value(
        "/roleManagement/directory/roleEligibilitySchedules",
        params={"$expand": "principal,roleDefinition"},
        token=pimAccessToken
    )

    activeAssignments = get_msgraph_value(
        "/roleManagement/directory/roleAssignmentSchedules",
        params={"$expand": "principal,roleDefinition"},
        token=pimAccessToken
    )

    if eligibleAssignments == None or activeAssignments == None:
        # PIM assignments could not be fetched, return
        return

    results = eligibleAssignments + activeAssignments
    roles = set([result["roleDefinition"]["displayName"]
                for result in results])
    for role in roles:
        assignments = [
            result for result in results if result["roleDefinition"]["displayName"] == role]
        count = len(assignments)
        rep.info(f"{role}: {count}")
        # If assignment expired, its not shown
        for assignment in assignments:
            principalId = assignment["principal"]["id"]
            displayName = assignment["principal"]["displayName"]
            type = assignment["principal"]["@odata.type"]

            # Parameters will be set for user objects
            lacksMfa = ""
            synced = ""

            if type == "#microsoft.graph.user":
                # for users, show UPN instead of ID
                principalId = assignment["principal"]["userPrincipalName"]
                friendlyType = "USER"
                # Check whether synced & no MFA methods
                userHasMfa = hasUserMFA(principalId, userRegistrationDetails)
                lacksMfa = "" if userHasMfa else f" {ORANGE}(No MFA Methods!){NC}"
                if userHasMfa == None:
                    lacksMfa = " (MFA unknown)"
                userObject = next(
                    (user for user in users if user["userPrincipalName"] == principalId), None)
                if userObject == None:
                    synced = f" {RED}(user not found!){NC}"
                else:
                    synced = f" {ORANGE}(synced!){NC}" if userObject["onPremisesSyncEnabled"] else ""
            elif type == "#microsoft.graph.group":
                friendlyType = "GROUP"
            elif type == "#microsoft.graph.servicePrincipal":
                friendlyType = "SERVICE_PRINCIPAL"
            else:
                friendlyType = "UNKNOWN_TYPE"

            isPermanent = f"{RED}[Permanent]{NC}" if assignment["scheduleInfo"]["expiration"]["type"] == "noExpiration" else ""
            assignmentState = "Active" if "assignmentType" in assignment else "Eligible"
            stateText = f"{GREEN}[{assignmentState}]{NC}"
            rep.raw(
                f"- [{friendlyType}] {principalId} ({displayName}) {isPermanent}{stateText}{synced}{lacksMfa}")


def enum_application_owners(servicePrincipal, tenantId, msGraphToken):
    sp = servicePrincipal
    displayName = sp["displayName"]
    # rep.header(f"Listing Owners of Service Principal and AppReg of SP with [{displayName}]")
    # get owner of service principal itself first
    objectId = sp["id"]
    owners = get_msgraph_value(
        f"/servicePrincipals/{objectId}/owners", {}, msGraphToken)
    if len(owners) > 0:
        rep.info(f"   {YELLOW}SP Owners{NC}")
        for owner in owners:
            ownerUPN = "Empty"
            try:
                ownerUPN = owner["userPrincipalName"]
            except:
                rep.info(
                    f"     Can not retrieve UPN of SP Owner, dumping id instead")
                ownerUPN = owner["id"]
            rep.info(f"     {CYAN}[{ownerUPN}]{NC}")

    # afterwards get corresponding appReg and its owners
    appId = sp["appId"]
    appRegs = get_msgraph_value(f"/applications/", {}, msGraphToken)
    for appReg in appRegs:
        if appReg["appId"] == appId:
            appRegObjectId = appReg["id"]
            owners = get_msgraph_value(
                f"/applications/{appRegObjectId}/owners", {}, msGraphToken)
            if len(owners) > 0:
                rep.info(f"   {YELLOW}AppReg Owners{NC}")
                for owner in owners:
                    appRegOwnerUPN = "Empty"
                    try:
                        appRegOwnerUPN = owner["userPrincipalName"]
                    except:
                        rep.info(
                            f"     Can not retrieve UPN of appReg Owner, dumping id instead")
                        appRegOwnerUPN = owner["id"]
                    rep.info(f"     {CYAN}[{appRegOwnerUPN}]{NC}")


def enum_app_api_permissions(servicePrincipals, tenantId, msGraphToken):
    rep.header(
        "ServicePrincipal API Permissions (only listing 'Application Permissions')")
    # In principle I am only interested in SPs from an AppReg. I can fetch the AppRegs `az rest --method get --url "{MS_GRAPH_API}/v1.0/myorganization/applications/"` and then lookout their SPs by checking the "appId" field of the SP object
    # Once I got the SP I can ask the appRoleAssignments like this `az rest --method get --url '{MS_GRAPH_API}/v1.0/servicePrincipals/<servicePrincipalId>/appRoleAssignments'` which get me value[] with objects like {resourceId,resourceDisplayName,appRoleId,...}. I need to pick the resourceId and the appRoleId to ask for the API-Permissions in the next request
    # I go {MS_GRAPH_API}/v1.0/servicePrincipals/<resourceId> and ask for the "appRoles" which look like {id,value,displayName}. The id is the "appRoleId" from before, the value is the API-Permission and the displayname a short description

    # SP that has an AppReg in the tenant
    internalSps = [
        sp for sp in servicePrincipals if sp["appOwnerOrganizationId"] == tenantId]
    # SP that has not an AppReg in the tenant. Nicht interessiert in Apps, die Microsoft gehören
    externalSps = [sp for sp in servicePrincipals if sp["appOwnerOrganizationId"] not in {
        tenantId, cfg.MICROSOFT_SERVICE_TENANT_ID}]

    if len(internalSps) > 0:
        rep.info(f"ServicePrincipals with an AppReg in this tenant")
    for sp in internalSps:
        id = sp["id"]
        displayName = sp["displayName"]
        appRoleAssignments = get_msgraph_value(
            f"/servicePrincipals/{id}/appRoleAssignments", {}, msGraphToken)
        if len(appRoleAssignments) > 0:
            for appRoleAssignment in appRoleAssignments:
                # For each appRoleAssignment
                # where does this app has an api permission (ID)
                resourceId = appRoleAssignment["resourceId"]
                # which permission does the app has
                appRoleId = appRoleAssignment["appRoleId"]
                # where does this app has an api permission
                resourceDisplayName = appRoleAssignment["resourceDisplayName"]
                resourceServicePrincipalAppRoles = next(
                    (sp["appRoles"] for sp in servicePrincipals if sp["id"] == resourceId), None)
                if (resourceServicePrincipalAppRoles != None):
                    appRole = next(
                        (appRole for appRole in resourceServicePrincipalAppRoles if appRole["id"] == appRoleId), None)
                    if appRole != None:
                        apiPermissionName = appRole["value"]
                        rep.info(
                            f"- {GREEN}[{displayName}]{NC} has {ORANGE}[{apiPermissionName}]{NC} in {CYAN}[{resourceDisplayName}]{NC}")
                    else:
                        # could not enumerate permission name, write down ID
                        rep.info(
                            f"- {GREEN}[{displayName}]{NC} has {ORANGE}[{appRoleId}]{NC} in {CYAN}[{resourceDisplayName}]{NC}")
            enum_application_owners(sp, tenantId, msGraphToken)
    if len(externalSps) > 0:
        rep.info(
            f"ServicePrincipals with an AppReg in a foreign, non-Microsoft tenant")
    for sp in externalSps:
        id = sp["id"]
        displayName = sp["displayName"]
        appRoleAssignments = get_msgraph_value(
            f"/servicePrincipals/{id}/appRoleAssignments", {}, msGraphToken)
        if len(appRoleAssignments) > 0:
            for appRoleAssignment in appRoleAssignments:
                # For each appRoleAssignment
                # where does this app has an api permission (ID)
                resourceId = appRoleAssignment["resourceId"]
                # which permission does the app has
                appRoleId = appRoleAssignment["appRoleId"]
                # where does this app has an api permission
                resourceDisplayName = appRoleAssignment["resourceDisplayName"]
                resourceServicePrincipalAppRoles = next(
                    (sp["appRoles"] for sp in servicePrincipals if sp["id"] == resourceId), None)
                if (resourceServicePrincipalAppRoles != None):
                    appRole = next(
                        (appRole for appRole in resourceServicePrincipalAppRoles if appRole["id"] == appRoleId), None)
                    if appRole != None:
                        apiPermissionName = appRole["value"]
                        rep.info(
                            f"- {GREEN}[{displayName}]{NC} has {ORANGE}[{apiPermissionName}]{NC} in {CYAN}[{resourceDisplayName}]{NC}")
                    else:
                        # could not enumerate permission name, write down ID
                        rep.info(
                            f"- {GREEN}[{displayName}]{NC} has {ORANGE}[{appRoleId}]{NC} in {CYAN}[{resourceDisplayName}]{NC}")
            enum_application_owners(sp, tenantId, msGraphToken)


def enum_administrative_units(msGraphToken):
    rep.header("Administrative Units")
    rep.link(
        f"Portal: {cfg.AZURE_PORTAL}/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/AdminUnit")
    admUnits = get_msgraph_value(
        "/directory/administrativeUnits", {}, msGraphToken)
    if admUnits == None:
        rep.error(f"Could not fetch Administrative Units")
        return
    directoryRoles = get_msgraph_value("/directoryRoles", {}, msGraphToken)
    if directoryRoles == None:
        rep.error(f"Could not fetch directory roles")
        return
    admUnitsNum = len(admUnits)
    if admUnitsNum == 0:
        rep.info(f"No Administrative Units found")
        return

    rep.info(f"{admUnitsNum} Administrative Units found")
    for unit in admUnits:
        displayName = unit["displayName"]
        admUnitId = unit["id"]
        membershipType = "Dynamic" if unit["membershipType"] == "Dynamic" else "Assigned"
        membershipRule = unit["membershipRule"] if unit["membershipRule"] != None else ""
        # Get Admin Roles (restricted to this administrative unit)
        admRoles = get_msgraph_value(
            f"/directory/administrativeUnits/{admUnitId}/scopedRoleMembers", {}, msGraphToken)
        ruleText = f": {membershipRule}" if membershipRule != "" else ""
        rep.info(f"- {GREEN}[{membershipType}] {displayName}{NC}{ruleText}")
        for admRole in admRoles:
            displayName = admRole["roleMemberInfo"]["displayName"]
            roleId = admRole["roleId"]
            roleName = next(
                (role["displayName"] for role in directoryRoles if role["id"] == roleId), None)
            rep.info(f"  - {displayName} has role {roleName}")


def enum_dynamic_groups(groups):
    if groups == None:
        return  # Couldnt fetch groups before
    dynamicGroups = [
        group for group in groups if "DynamicMembership" in group["groupTypes"]]
    rep.header("Dynamic groups")
    rep.link("Exploitation: https://cloud.hacktricks.xyz/pentesting-cloud/azure-pentesting/dynamic-groups")
    rep.info(f"{len(dynamicGroups)} Dynamic Groups found")
    if len(dynamicGroups) == 0:
        return
    for group in dynamicGroups:
        displayName = group["displayName"]
        membershipRule = group["membershipRule"]
        groupType = "Security"
        if "Unified" in group["groupTypes"]:
            groupType = "m365"
        rep.info(f"- {GREEN}[{groupType}] {displayName}{NC}: {membershipRule}")


def enum_named_locations(msGraphToken):
    rep.header("Named Locations")
    rep.link(
        f"Portal: {cfg.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_ConditionalAccess/NamedLocationsBlade")

    namedLocations = get_msgraph_value(
        "/identity/conditionalAccess/namedLocations", {}, msGraphToken)

    if namedLocations == None:
        rep.error(f"Could not fetch named locations")
        return

    if len(namedLocations) == 0:
        rep.info("No named locations")
        return

    rep.info(f"{len(namedLocations)} Named locations found")
    for location in namedLocations:
        displayName = location["displayName"]
        locationType = location["@odata.type"]
        if locationType == "#microsoft.graph.ipNamedLocation":
            ranges = ' '.join([ipRange["cidrAddress"]
                              for ipRange in location["ipRanges"]])
            isTrusted = "Trusted" if location["isTrusted"] else "Not trusted"
            rep.info(f"- {GREEN}[IP - {isTrusted}] {displayName}{NC} {ranges}")
        elif locationType == "#microsoft.graph.countryNamedLocation":
            countries = ' '.join(location["countriesAndRegions"])
            rep.info(f"- {GREEN}[COUNTRY] {displayName}{NC} {countries}")
        else:
            rep.info(
                f"- {GREEN}[Unknown Location type: {locationType}] {displayName}{NC}")


def enum_conditional_access(tenantId, aadGraphToken):
    rep.header("Conditional Access Policies")
    rep.link(
        f"Portal: {cfg.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies")

    allPolicies = get_aadgraph_value("/policies", {}, tenantId, aadGraphToken)
    if allPolicies == None:
        rep.error("Could not fetch Conditional Access Policies")
        return
    # what are the other policies??
    conditionalAccessPolicies = [
        policy for policy in allPolicies if policy["policyType"] == 18]
    if len(conditionalAccessPolicies) == 0:
        rep.info("No Conditional Access Policies")
        return

    rep.info(f"{len(conditionalAccessPolicies)} Conditional Access Policies found")
    for cap in conditionalAccessPolicies:
        displayName = cap["displayName"]
        detailsRaw = cap["policyDetail"][0]
        details = json.loads(detailsRaw)
        isEnabled = details["State"]
        color = RED
        if isEnabled == "Enabled":
            color = GREEN
        elif isEnabled == "Reporting":
            color = ORANGE
        rep.info(f"- {color}[{isEnabled}]{NC} {GREEN}\"{displayName}\"{NC}")


def enum_devices(msGraphToken):
    rep.header("Devices")
    rep.link(
        f"Portal: {cfg.AZURE_PORTAL}/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/Devices/menuId~/null")
    devices = get_msgraph_value("/devices", {"$top": "999"}, msGraphToken)

    if devices == None:
        rep.error("Could not fetch devices")
        return

    rep.info(f"Number of devices: {len(devices)}")
    rep.info("Devices per Join-Type:")
    registeredDevices = [
        device for device in devices if device["trustType"] == "Workplace"]
    joinedDevices = [
        device for device in devices if device["trustType"] == "AzureAd"]
    hybridJoinedDevices = [
        device for device in devices if device["trustType"] == "ServerAd"]
    rep.info(f"- Registered: {len(registeredDevices)}")
    rep.info(f"- Joined: {len(joinedDevices)}")
    rep.info(f"- Hybrid-Joined: {len(hybridJoinedDevices)}")
    managedDevices = [
        device for device in devices if device["isManaged"] == True]
    managedPercent = "-"
    if len(devices) != 0:
        managedPercent = round(len(managedDevices) / len(devices) * 100, 2)
    rep.info(
        f"Managed devices: {len(managedDevices)}/{len(devices)} ({managedPercent} %)")
    compliantDevices = [
        device for device in devices if device["isCompliant"] == True]
    nonCompliantDevices = [
        device for device in devices if device["isCompliant"] == False]
    deviceNumWithComplianceData = len(
        compliantDevices) + len(nonCompliantDevices)
    compliantPercent = "-"
    if deviceNumWithComplianceData != 0:
        compliantPercent = round(
            len(compliantDevices) / deviceNumWithComplianceData * 100, 2)
    rep.info(
        f"Compliant devices: {len(compliantDevices)}/{deviceNumWithComplianceData} ({compliantPercent} %)")

    current_datetime = datetime.utcnow()
    # Calculate 6 months ago from the current date
    six_months_ago = current_datetime - \
        timedelta(days=6*30)  # Approximate 30 days in a month
    formatted_datetime = six_months_ago.strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    staleDevices = get_msgraph_value("/devices", {
        "$top": "999",
        "$filter": f"approximateLastSignInDateTime le {formatted_datetime}"
    }, msGraphToken)
    staleProcent = "-"
    if len(devices) != 0:
        staleProcent = round(len(staleDevices)/len(devices) * 100, 2)
    rep.info(
        f"Stale Devices: {len(staleDevices)}/{len(devices)} ({staleProcent} %) -- last activity older than 6 months")


def search_principal_properties(groups, servicePrincipals, msGraphToken):
    rep.header("Juicy Info in User, Group and Apps Properties")
    rep.info("Searching for juicy info in principal properties ...")
    keywords = ["passwo", "credential", "access",
                "zugang", "login", "anmeld", "initial"]

    usersFull = get_msgraph_value("/users", {}, msGraphToken, "beta")
    if usersFull == None:
        rep.error(f"Could not fetch users")
    else:
        for user in usersFull:
            for key in user:
                # Exclude "passwordPolicies" string which leads to false positives
                if (isinstance(user[key], str) and key != "passwordPolicies"):
                    if any(keyword in user[key].lower() for keyword in keywords):
                        upn = user["userPrincipalName"]
                        rep.info(
                            f"[USER] {upn} => {RED}({key}): {user[key]}{NC}")
    if groups != None:
        for group in [group for group in groups if group["description"] != None]:
            if any(keyword in group["description"].lower() for keyword in keywords):
                displayName = group["displayName"]
                desc = group["description"]
                rep.info(
                    f"[GROUP] {displayName} => {RED}(description): {desc}{NC}")
    if servicePrincipals != None:
        for spn in servicePrincipals:
            if spn["notes"] != None:
                if any(keyword in spn["notes"].lower() for keyword in keywords):
                    displayName = spn["displayName"]
                    notes = spn["notes"]
                    rep.info(
                        f"[APP] {displayName} => {RED}(notes): {notes}{NC}")


def print_banner():
    if args.no_color:
        banner = '''
        AzurEnum
        Created by Enrique Hernández (SySS GmbH)
        '''
    else:
        banner = f'''

         ████████ ██████        
       ██████████ ████████     
     ████████████ ██████████    
   ██████{RED}██████{NC}██ █████  █  █   
  █████{RED}███{NC}███████ █ █ █ ██ ███   AzurEnum
 ██████{RED}███{NC}███████ ██ ███ ██ ███   Created by Enrique Hernández (SySS GmbH)
 ████████{RED}█████{NC}███ █ ███  █  ███  
 ████████████{RED}███{NC}█
  ███████████{RED}███{NC}█
   █████{RED}███████{NC}██
     ████████████ 
       ▄▄▄▄▄▄▄▄▄▄ 
         ████████ 

        '''

    print(banner)


def main():

    global args, rep
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=100))
    parser.add_argument("-o", "--output-text", help="specify filename to save TEXT output",
                        default=None, type=argparse.FileType('w'))
    parser.add_argument("-j", "--output-json", help="specify filename to save JSON output (only findings related to insecure settings will be written!)",
                        default=None, type=argparse.FileType('w'))
    parser.add_argument("-nc", "--no-color",
                        help="don't use colors", action='store_true')
    parser.add_argument("-ua", "--user-agent",
                        help="specify user agent (default is MS-Edge on Windows 10)", default=None)
    parser.add_argument(
        "-t", "--tenant-id", help="specify tenant to authenticate to (needed for ROPC authentication or when authenticating to a non-native tenant of the given user)", default=None)
    parser.add_argument(
        "-u", "--upn", help="specify user principal name to use in ROPC authentication", default=None)
    parser.add_argument(
        "-p", "--password", help="specify password to use in ROPC authentication", default=None)
    # parser.add_argument("-v", "--verbose", help="enable debug printing", default=None)
    # parser.add_argument("-cache", "--cache", help="caches the auth token", default=None)

    args = parser.parse_args()

    rep = Reporter(out_text=args.output_text, out_json=args.output_json)

    # Set UA if given
    if args.user_agent != None:
        global session
        session.headers.update({"User-Agent": args.user_agent})

    # Set Colors
    if args.no_color:
        unset_colors()
    elif IS_WINDOWS:
        # Activate colors for the terminal
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

    cache_path = os.path.expanduser("~/.azurenum_token.json")

    auth_manager = AuthManager(
        tenant_id=args.tenant_id,
        session=session,
        cache_path=cache_path
    )

    try:
        if args.upn and args.password and args.tenant_id:
            auth_manager.bootstrap(
                client_id=cfg.OFFICE_CLIENT_ID,
                scopes=cfg.SCOPE_MS_GRAPH,
                rep=rep,
                device_code=False,
                username=args.upn,
                password=args.password,
            )
        else:
            auth_manager.bootstrap(
                client_id=cfg.OFFICE_CLIENT_ID,
                scopes=cfg.SCOPE_MS_GRAPH,
                rep=rep,
                device_code=True,
            )
    except AuthError as e:
        rep.error(str(e))
        sys.exit(1)

    print_banner()

    try:
        msGraphToken = auth_manager.token_for(Resource.GRAPH, rep=rep)
    except AuthError as e:
        rep.error(f"Could not request Microsoft Graph token: {e}")
        sys.exit(1)

    try:
        aadGraphToken = auth_manager.token_for(Resource.AAD_GRAPH, rep=rep)
    except AuthError as e:
        rep.error(f"Could not request AAD Graph token: {e}")
        aadGraphToken = None

    try:
        armToken = auth_manager.token_for(Resource.ARM, rep=rep)
    except AuthError as e:
        rep.error(f"Could not request ARM token: {e}")
        armToken = None

    try:
        pimToken = auth_manager.token_for(
            Resource.GRAPH, rep=rep, client_id=cfg.MANAGED_MEETING_ROOMS_CLIENT_ID
        )
    except AuthError as e:
        rep.error(f"Could not request PIM token: {e}")
        pimToken = None

    app = auth_manager._app(cfg.OFFICE_CLIENT_ID)
    accounts = app.get_accounts()
    myUpn = (accounts[0].get("username") if accounts else "unknown")

    rep.info(f"Running as {myUpn}")
    rep.info(f"Gathering information ............")

    gc = MSGraphClient(token=msGraphToken, rep=rep, session=session)
    gb = MSGraphBetaClient(token=msGraphToken, session=session)

    # Gather some informations that gets reused by other functions
    info = {
        "org": gc.organization(),
        "groups": gc.groups(),
        "service_principals": gc.service_principals(),
        "group_settings": gc.group_settings(),
        "users": gc.users(params={"$select": "displayName,id,userPrincipalName,userType,onPremisesSyncEnabled"}),
        "user_registration_details": gc.user_reg_details(),
        "auth_policy": gb.auth_policy()
    }

    for name, val in info.items():
        if not val:
            rep.error(f"Could not fetch {name.replace('_',' ')}")

    org = info["org"]
    tenant_id = org["id"]
    groups = info["groups"]
    service_principals = info["service_principals"]
    group_settings = info["group_settings"]
    users = info["users"]
    user_registration_details = info["user_registration_details"]
    auth_policy = info["auth_policy"]

    # Basic Tenant Info
    basic_info(org, groups, service_principals, group_settings, users,
               user_registration_details, msGraphToken, msGraphToken, armToken)

    # General user settings
    enum_user_settings(auth_policy, group_settings)

    # Device Settings
    enum_device_settings(auth_policy, tenant_id, aadGraphToken)

    # Administrators
    enum_admin_roles(msGraphToken, user_registration_details)

    # PIM Assignments
    enum_pim_assignments(users, pimToken, user_registration_details)

    # API-Permissions
    if service_principals != None:
        enum_app_api_permissions(service_principals, tenant_id, msGraphToken)

    # Administrative Units
    enum_administrative_units(msGraphToken)

    # Dynamic groups
    enum_dynamic_groups(groups)

    # Named locations
    enum_named_locations(msGraphToken)

    # Conditional Access
    enum_conditional_access(tenant_id, aadGraphToken)

    # Devices
    enum_devices(msGraphToken)

    # Search principals properties for creds
    search_principal_properties(groups, service_principals, msGraphToken)

    # Saves output text / json
    rep.save()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        if rep:
            rep.info('KeyboardInterrupt... Exit now!')
        else:
            print('KeyboardInterrupt... Exit now!')
        sys.exit(1)
