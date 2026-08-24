# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-drata",
    "name": "Drata",
    "type": "inbound",
    "description": "Imports assets from Drata.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    # A BACKSTOP, not the primary guard: the walk's real runaway protection is
    # the repeated-page check in the loop, which notices a Drata that ignores
    # `page` after two requests. 200,000 pages x 50 rows = 10,000,000 assets,
    # past any real Drata deployment; reaching it raises rather than quietly
    # truncating.
    "maxPages": 200000,
    "params": [
        {
            "key": "url",
            "label": "Drata API URL",
            "type": "url",
            "required": False,
            "default": "https://public-api.drata.com",
            "placeholder": "https://public-api.drata.com",
            "description": "Drata's API endpoint. Override only for a regional or non-production deployment.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'to_custom_attributes')
load('net', 'network_interface')
load('http', 'get_json', 'bearer')
load('kwargs', 'get_http_options')

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a regional or non-production deployment can be reached
# without editing the script.
DEFAULT_DRATA_URL = 'https://public-api.drata.com'

PAGE_SIZE = 50

def retrieved_of(retrieved, total):
    """The "Retrieved X/Y available assets" half of a truncation message.

    A truncated run has to say how much of the estate it actually got: a bare
    count tells the reader nothing about whether the import is nearly complete
    or stopped at the first percent. Where the API reports no total, say so
    plainly rather than printing a bare slash or inventing a denominator.
    """
    if type(total) == 'int' and total > 0:
        return 'Retrieved {}/{} available assets'.format(retrieved, total)
    return 'Retrieved {} assets; the API does not report a total'.format(retrieved)

def page_signature(rows):
    """A cheap fingerprint of one page: its length and the ids at either end.

    Two consecutive pages sharing a fingerprint means the server re-served one
    page rather than advancing through the collection. Comparing ends rather
    than every row keeps this O(1) per page, and it is enough for the failure it
    guards against -- a tenant that ignores `page` returns byte-identical
    responses, not a rearrangement of one.
    """
    if not rows:
        return 'empty'
    first = rows[0]
    last = rows[-1]
    first_id = first.get('id', '') if type(first) == 'dict' else ''
    last_id = last.get('id', '') if type(last) == 'dict' else ''
    return '{}|{}|{}'.format(len(rows), first_id, last_id)

def build_assets(assets_json):
    assets_import = []
    for item in assets_json:
        # A non-object element in the data array has no id to key on and would
        # abort the run at .get, losing this page and every page after it.
        if type(item) != 'dict':
            print("drata: skipping non-object asset row")
            continue
        id = item.get('id')
        if not id:
            print("drata: skipping asset with no id: name=" + str(item.get('name', '')))
            continue
        hostname = item.get('name', '')
        description = item.get('description', '')
        asset_type = item.get('assetType', '')
        asset_provider = item.get('assetProvider', '')
        employment_status = item.get('employmentStatus', '')
        created_at = item.get('createdAt', '')
        updated_at = item.get('updatedAt', '')
        removed_at = item.get('removedAt', '')

        # The interface is built further down, once the device block has been
        # read. Drata publishes no IP address, and a synthetic 127.0.0.1 used to
        # be placed here instead: because loopback is identical on every host,
        # IP matching pulled every Drata asset onto the same existing asset and
        # merged unrelated machines. Never put a placeholder address on a
        # network interface.

        # Every field below is assigned only inside a conditional -- the device
        # block, or one branch of the compliance-check loop -- and Starlark has no
        # concept of an unset local. An asset missing its device block, or missing
        # any one of the six check types, therefore aborted the entire run with
        # 'referenced before assignment'. Defaulting them here keeps a partial
        # record importable as a partial record.
        macs = []
        agent_version = ''
        apps_count = ''
        deleted_at = ''
        encryption_enabled = ''
        firewall_enabled = ''
        gatekeeper_enabled = ''
        is_device_compliant = ''
        last_checked_at = ''
        model = ''
        os_version = ''
        serial_number = ''
        source_type = ''
        deviceComplianceCheckAgentInstalledCreatedAt = ''
        deviceComplianceCheckAgentInstalledExpiresAt = ''
        deviceComplianceCheckAgentInstalledId = ''
        deviceComplianceCheckAgentInstalledLastCheckedAt = ''
        deviceComplianceCheckAgentInstalledStatus = ''
        deviceComplianceCheckAgentInstalledType = ''
        deviceComplianceCheckAgentInstalledUpdatedAt = ''
        deviceComplianceCheckAntivirusCreatedAt = ''
        deviceComplianceCheckAntivirusExpiresAt = ''
        deviceComplianceCheckAntivirusId = ''
        deviceComplianceCheckAntivirusLastCheckedAt = ''
        deviceComplianceCheckAntivirusStatus = ''
        deviceComplianceCheckAntivirusType = ''
        deviceComplianceCheckAntivirusUpdatedAt = ''
        deviceComplianceCheckAutoUpdatesCreatedAt = ''
        deviceComplianceCheckAutoUpdatesExpiresAt = ''
        deviceComplianceCheckAutoUpdatesId = ''
        deviceComplianceCheckAutoUpdatesLastCheckedAt = ''
        deviceComplianceCheckAutoUpdatesStatus = ''
        deviceComplianceCheckAutoUpdatesType = ''
        deviceComplianceCheckAutoUpdatesUpdatedAt = ''
        deviceComplianceCheckDiskEncryptionCreatedAt = ''
        deviceComplianceCheckDiskEncryptionExpiresAt = ''
        deviceComplianceCheckDiskEncryptionId = ''
        deviceComplianceCheckDiskEncryptionLastCheckedAt = ''
        deviceComplianceCheckDiskEncryptionStatus = ''
        deviceComplianceCheckDiskEncryptionType = ''
        deviceComplianceCheckDiskEncryptionUpdatedAt = ''
        deviceComplianceCheckLockScreenCreatedAt = ''
        deviceComplianceCheckLockScreenExpiresAt = ''
        deviceComplianceCheckLockScreenId = ''
        deviceComplianceCheckLockScreenLastCheckedAt = ''
        deviceComplianceCheckLockScreenStatus = ''
        deviceComplianceCheckLockScreenType = ''
        deviceComplianceCheckLockScreenUpdatedAt = ''
        deviceComplianceCheckPasswordManagerCreatedAt = ''
        deviceComplianceCheckPasswordManagerExpiresAt = ''
        deviceComplianceCheckPasswordManagerId = ''
        deviceComplianceCheckPasswordManagerLastCheckedAt = ''
        deviceComplianceCheckPasswordManagerStatus = ''
        deviceComplianceCheckPasswordManagerType = ''
        deviceComplianceCheckPasswordManagerUpdatedAt = ''
        owner_created_at = ''
        owner_email = ''
        owner_first_name = ''
        owner_id = ''
        owner_last_name = ''
        owner_roles = ''
        owner_terms_agreed = ''
        owner_updated_at = ''
        # The device block must be an object: present-but-null defeats the .get
        # default, and .get on a scalar aborts the run.
        device = item.get('device', {})
        if type(device) != 'dict':
            device = {}
        if device:
            os_version = device.get('osVersion', '')
            serial_number = device.get('serialNumber', '')
            model = device.get('model', '')
            agent_version = device.get('agentVersion', '')
            macs = device.get('macAddress', [])
            encryption_enabled = device.get('encryptionEnabled', '')
            firewall_enabled = device.get('firewallEnabled', '')
            gatekeeper_enabled = device.get('gateKeeperEnabled', '')
            last_checked_at = device.get('lastCheckedAt', '')
            source_type = device.get('sourceType', '')
            created_at = device.get('createdAt', '')
            updated_at = device.get('updatedAt', '')
            deleted_at = device.get('deletedAt', '')
            apps_count = device.get('appsCount', '')
            is_device_compliant = device.get('isDeviceCompliant', '')

            # parse Drata compliance checks; will likely need updated based on your configuration
            # A present-but-null complianceChecks value defeats a .get default,
            # and iterating anything but a list of objects aborts the run at
            # check.get -- so the shape is screened before the loop.
            compliance_checks = device.get('complianceChecks')
            if type(compliance_checks) != 'list':
                compliance_checks = []
            if compliance_checks:
                for check in compliance_checks:
                    if type(check) != 'dict':
                        print('drata: skipping malformed compliance check entry')
                        continue
                    check_type = check.get('type', '')
                    if check_type == 'AGENT_INSTALLED':
                        deviceComplianceCheckAgentInstalledCreatedAt = check.get('createdAt', '')
                        deviceComplianceCheckAgentInstalledExpiresAt = check.get('createdAt', '')
                        deviceComplianceCheckAgentInstalledId = check.get('id', '')
                        deviceComplianceCheckAgentInstalledLastCheckedAt = check.get('lastCheckedAt', '')
                        deviceComplianceCheckAgentInstalledStatus = check.get('status', '')
                        deviceComplianceCheckAgentInstalledType = check.get('type', '')
                        deviceComplianceCheckAgentInstalledUpdatedAt = check.get('updatedAt', '')  
                    elif check_type == 'PASSWORD_MANAGER':
                        deviceComplianceCheckPasswordManagerCreatedAt = check.get('createdAt', '')
                        deviceComplianceCheckPasswordManagerExpiresAt = check.get('createdAt', '')
                        deviceComplianceCheckPasswordManagerId = check.get('id', '')
                        deviceComplianceCheckPasswordManagerLastCheckedAt = check.get('lastCheckedAt', '')
                        deviceComplianceCheckPasswordManagerStatus = check.get('status', '')
                        deviceComplianceCheckPasswordManagerType = check.get('type', '')
                        deviceComplianceCheckPasswordManagerUpdatedAt = check.get('updatedAt', '')                      
                    elif check_type == 'HDD_ENCRYPTION':
                        deviceComplianceCheckDiskEncryptionCreatedAt = check.get('createdAt', '')
                        deviceComplianceCheckDiskEncryptionExpiresAt = check.get('createdAt', '')
                        deviceComplianceCheckDiskEncryptionId = check.get('id', '')
                        deviceComplianceCheckDiskEncryptionLastCheckedAt = check.get('lastCheckedAt', '')
                        deviceComplianceCheckDiskEncryptionStatus = check.get('status', '')
                        deviceComplianceCheckDiskEncryptionType = check.get('type', '')
                        deviceComplianceCheckDiskEncryptionUpdatedAt = check.get('updatedAt', '')  
                    elif check_type == 'ANTIVIRUS':
                        deviceComplianceCheckAntivirusCreatedAt = check.get('createdAt', '')
                        deviceComplianceCheckAntivirusExpiresAt = check.get('createdAt', '')
                        deviceComplianceCheckAntivirusId = check.get('id', '')
                        deviceComplianceCheckAntivirusLastCheckedAt = check.get('lastCheckedAt', '')
                        deviceComplianceCheckAntivirusStatus = check.get('status', '')
                        deviceComplianceCheckAntivirusType = check.get('type', '')
                        deviceComplianceCheckAntivirusUpdatedAt = check.get('updatedAt', '')  
                    elif check_type == 'AUTO_UPDATES':
                        deviceComplianceCheckAutoUpdatesCreatedAt = check.get('createdAt', '')
                        deviceComplianceCheckAutoUpdatesExpiresAt = check.get('createdAt', '')
                        deviceComplianceCheckAutoUpdatesId = check.get('id', '')
                        deviceComplianceCheckAutoUpdatesLastCheckedAt = check.get('lastCheckedAt', '')
                        deviceComplianceCheckAutoUpdatesStatus = check.get('status', '')
                        deviceComplianceCheckAutoUpdatesType = check.get('type', '')
                        deviceComplianceCheckAutoUpdatesUpdatedAt = check.get('updatedAt', '')  
                    elif check_type == 'LOCK_SCREEN':
                        deviceComplianceCheckLockScreenCreatedAt = check.get('createdAt', '')
                        deviceComplianceCheckLockScreenExpiresAt = check.get('createdAt', '')
                        deviceComplianceCheckLockScreenId = check.get('id', '')
                        deviceComplianceCheckLockScreenLastCheckedAt = check.get('lastCheckedAt', '')
                        deviceComplianceCheckLockScreenStatus = check.get('status', '')
                        deviceComplianceCheckLockScreenType = check.get('type', '')
                        deviceComplianceCheckLockScreenUpdatedAt = check.get('updatedAt', '')  
                    else:
                        # `type` here was the Starlark builtin, not the check's
                        # type, and concatenating a builtin to a string aborts
                        # the script -- so the first device carrying a
                        # compliance check Drata added after this code was
                        # written took the whole import down, including every
                        # device still unprocessed.
                        print('drata: unrecognized compliance check: ' + str(check_type))

        owner = item.get('owner', {})
        if type(owner) != 'dict':
            owner = {}
        if owner:
            owner_id = owner.get('id', '')
            owner_email = owner.get('email', '')
            owner_first_name = owner.get('firstName', '')
            owner_last_name = owner.get('lastName', '')
            owner_terms_agreed = owner.get('drataTermsAgreedAt', '')
            owner_created_at = owner.get('createdAt', '')
            owner_updated_at = owner.get('updatedAt', '')
            owner_roles = owner.get('roles', [])

        # Build the interface now that the device block above has populated the
        # MAC list. An asset with no MAC gets no interface at all rather than a
        # placeholder one. The field is named macAddress in the singular, so it
        # is coerced to a list rather than iterated directly: iterating a string
        # would walk its characters.
        mac_list = macs if type(macs) == "list" else ([macs] if macs else [])
        networks = []
        for m in mac_list:
            nic = network_interface(mac=str(m))
            if nic:
                networks.append(nic)

        assets_import.append(
            ImportAsset(
                id=str(id),
                hostnames=[hostname],
                networkInterfaces=networks,
                os=os_version,    
                customAttributes=to_custom_attributes({
                    "description":description,
                    "assetType":asset_type,
                    "asset_provider":asset_provider,
                    "employmentStatus":employment_status,
                    "createdAt":created_at,
                    "updatedAt":updated_at,
                    "removedAt":removed_at,
                    "device.os":os_version,
                    "device.serialNumber":serial_number,
                    "device.model":model,
                    "device.agentVersion":agent_version,
                    "device.macs":macs,
                    "device.encryptionEnabled":encryption_enabled,
                    "device.firewallEnabled":firewall_enabled,
                    "device.gatekeeperEnabled":gatekeeper_enabled,
                    "device.lastCheckedAat":last_checked_at,
                    "device.sourceType":source_type,
                    "device.createdAt":created_at,
                    "device.updatedAt":updated_at,
                    "device.deletedAt":deleted_at,
                    "device.appsCount":apps_count,
                    "device.isDeviceCompliant":is_device_compliant,
                    "device.complianceCheckAgentInstalledCreatedAt":deviceComplianceCheckAgentInstalledCreatedAt,
                    "device.complianceCheckAgentInstalledExpiresAt":deviceComplianceCheckAgentInstalledExpiresAt,
                    "device.complianceCheckAgentInstalledId":deviceComplianceCheckAgentInstalledId,
                    "device.complianceCheckAgentInstalledLastCheckedAt":deviceComplianceCheckAgentInstalledLastCheckedAt,
                    "device.complianceCheckAgentInstalledStatus":deviceComplianceCheckAgentInstalledStatus,
                    "device.complianceCheckAgentInstalledType":deviceComplianceCheckAgentInstalledType,
                    "device.complianceCheckAgentInstalledUpdatedAt":deviceComplianceCheckAgentInstalledUpdatedAt,
                    "device.complianceCheckPasswordManagerCreatedAt":deviceComplianceCheckPasswordManagerCreatedAt,
                    "device.complianceCheckPasswordManagerExpiresAt":deviceComplianceCheckPasswordManagerExpiresAt,
                    "device.complianceCheckPasswordManagerId":deviceComplianceCheckPasswordManagerId,
                    "device.complianceCheckPasswordManagerLastCheckedAt":deviceComplianceCheckPasswordManagerLastCheckedAt,
                    "device.complianceCheckPasswordManagerStatus":deviceComplianceCheckPasswordManagerStatus,
                    "device.complianceCheckPasswordManagerType":deviceComplianceCheckPasswordManagerType,
                    "device.complianceCheckPasswordManagerUpdatedAt":deviceComplianceCheckPasswordManagerUpdatedAt,
                    "device.complianceCheckDiskEncryptionCreatedAt":deviceComplianceCheckDiskEncryptionCreatedAt,
                    "device.complianceCheckDiskEncryptionExpiresAt":deviceComplianceCheckDiskEncryptionExpiresAt,
                    "device.complianceCheckDiskEncryptionId":deviceComplianceCheckDiskEncryptionId,
                    "device.complianceCheckDiskEncryptionLastCheckedAt":deviceComplianceCheckDiskEncryptionLastCheckedAt,
                    "device.complianceCheckDiskEncryptionStatus":deviceComplianceCheckDiskEncryptionStatus,
                    "device.complianceCheckDiskEncryptionType":deviceComplianceCheckDiskEncryptionType,
                    "device.complianceCheckDiskEncryptionUpdatedAt":deviceComplianceCheckDiskEncryptionUpdatedAt,
                    "device.complianceCheckAntivirusCreatedAt":deviceComplianceCheckAntivirusCreatedAt,
                    "device.complianceCheckAntivirusExpiresAt":deviceComplianceCheckAntivirusExpiresAt,
                    "device.complianceCheckAntivirusId":deviceComplianceCheckAntivirusId,
                    "device.complianceCheckAntivirusLastCheckedAt":deviceComplianceCheckAntivirusLastCheckedAt,
                    "device.complianceCheckAntivirusStatus":deviceComplianceCheckAntivirusStatus,
                    "device.complianceCheckAntivirusType":deviceComplianceCheckAntivirusType,
                    "device.complianceCheckAntivirusUpdatedAt":deviceComplianceCheckAntivirusUpdatedAt,
                    "device.complianceCheckAutoUpdatesCreatedAt":deviceComplianceCheckAutoUpdatesCreatedAt,
                    "device.complianceCheckAutoUpdatesExpiresAt":deviceComplianceCheckAutoUpdatesExpiresAt,
                    "device.complianceCheckAutoUpdatesId":deviceComplianceCheckAutoUpdatesId,
                    "device.complianceCheckAutoUpdatesLastCheckedAt":deviceComplianceCheckAutoUpdatesLastCheckedAt,
                    "device.complianceCheckAutoUpdatesStatus":deviceComplianceCheckAutoUpdatesStatus,
                    "device.complianceCheckAutoUpdatesType":deviceComplianceCheckAutoUpdatesType,
                    "device.complianceCheckAutoUpdatesUpdatedAt":deviceComplianceCheckAutoUpdatesUpdatedAt,
                    "device.complianceCheckLockScreenCreatedAt":deviceComplianceCheckLockScreenCreatedAt,
                    "device.complianceCheckLockScreenExpiresAt":deviceComplianceCheckLockScreenExpiresAt,
                    "device.complianceCheckLockScreenId":deviceComplianceCheckLockScreenId,
                    "device.complianceCheckLockScreenLastCheckedAt":deviceComplianceCheckLockScreenLastCheckedAt,
                    "device.complianceCheckLockScreenStatus":deviceComplianceCheckLockScreenStatus,
                    "device.complianceCheckLockScreenType":deviceComplianceCheckLockScreenType,
                    "device.complianceCheckLockScreenUpdatedAt":deviceComplianceCheckLockScreenUpdatedAt,
                    "owner.id":owner_id,
                    "owner.email":owner_email,
                    "owner.firstName":owner_first_name,
                    "owner.lastName":owner_last_name,
                    "owner.drataTermsAgreedAt":owner_terms_agreed,
                    "owner.createdAt":owner_created_at,
                    "owner.updatedAt":owner_updated_at,
                    "owner.roles":[owner_roles]
                }),
            )
        )
    return assets_import

# Build runZero network interfaces; shouldn't need to touch this
def main(**kwargs):
    token = kwargs['api_token']
    # The platform applies the CONFIG default, but fall back explicitly so the
    # script still works if it is invoked without one.
    base_url = (kwargs.get('url') or DEFAULT_DRATA_URL).rstrip('/')
    http_options = get_http_options(kwargs, headers={"Authorization": bearer(token)})

    # Get assets
    filter = 'assetClassType=HARDWARE&employmentStatus=CURRENT_EMPLOYEE'

    page_size = PAGE_SIZE
    reported = 0
    last_signature = ""
    # Drata reports the size of the whole collection alongside every page. It is
    # captured so a truncated run can say what fraction of the estate it got,
    # rather than a bare count the reader cannot judge.
    total_count = None

    # CONFIG maxPages backstops the walk via pager(); the repeated-page check
    # below remains the primary runaway guard.
    p = pager("assets")
    while p.next():
        page = p.page
        url = '{}/{}?{}&page={}&limit={}'.format(base_url, 'public/assets', filter, page, page_size)
        data, err = get_json(url, **http_options)
        if err:
            print('failed to retrieve assets:', err)
            return None

        # The documented response is an object carrying "data" and "total";
        # reading .get off a list would abort the script.
        if type(data) != 'dict':
            print('drata: unexpected response shape, wanted an object')
            return None

        reported_total = data.get('total')
        if type(reported_total) == 'int' and reported_total >= 0:
            total_count = reported_total

        results_json = data.get('data') or []
        if type(results_json) != 'list':
            print('drata: unexpected data field shape, wanted a list')
            break
        if not results_json:
            break

        # THE PRIMARY RUNAWAY GUARD. A page identical to the one before it means
        # Drata is ignoring `page` and re-serving the same rows, so the walk is
        # not advancing and continuing can only re-report assets already
        # reported. Checked BEFORE the page is reported, so the repeated rows
        # never reach runZero, and it can never truncate genuine data: it only
        # fires on a page that adds nothing. It catches the stuck tenant in two
        # requests where the page ceiling would take 200,000.
        signature = page_signature(results_json)
        if signature == last_signature:
            print('drata: paging stopped after {} pages: the API returned the same page twice. {}'.format(
                page, retrieved_of(reported, total_count)))
            break
        last_signature = signature

        # Page on the data itself. This previously advanced only when total was
        # exactly 9999999 -- a sentinel from a mock -- so every realistic
        # response fell through to "unexpected value returned for total" and the
        # integration imported nothing at all.
        # Build and stream each page via report_assets so the full asset set is
        # never held in memory.
        reported += report_assets(build_assets(results_json))
        if len(results_json) < page_size:
            break

    if not reported:
        print('no assets')

    return None