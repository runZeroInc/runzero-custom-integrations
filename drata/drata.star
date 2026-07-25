# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-drata",
    "name": "Drata",
    "type": "inbound",
    "description": "Imports assets from Drata.",
    "version": "26061000",
    "minVersion": "5.0.260723.0",
    "params": [
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
load('flatten_json', 'flatten')

DRATA_URL = 'https://public-api.drata.com'

def build_assets(assets_json):
    assets_import = []
    for item in assets_json:
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

        ips = ['127.0.0.1']
        macs = []
        if macs:
            #for m in macs:
            network = network_interface(ips=ips, mac=macs)
        else:
            network = network_interface(ips=ips, mac=None)

        device = []
        device = item.get('device', {})
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
            compliance_checks = []
            compliance_checks = device.get('complianceChecks', {})
            if compliance_checks:
                for check in compliance_checks:
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
                        print('unrecognized compliance check: ' + type)              

        owner = []
        owner = item.get('owner', {})
        if owner:
            owner_id = owner.get('id', '')
            owner_email = owner.get('email', '')
            owner_first_name = owner.get('firstName', '')
            owner_last_name = owner.get('lastName', '')
            owner_terms_agreed = owner.get('drataTermsAgreedAt', '')
            owner_created_at = owner.get('createdAt', '')
            owner_updated_at = owner.get('updatedAt', '')
            owner_roles = owner.get('roles', [])

        assets_import.append(
            ImportAsset(
                id=str(id),
                hostnames=[hostname],
                networkInterfaces=[network],
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
    http_options = get_http_options(kwargs, headers={"Authorization": bearer(token)})
        
    # Get assets
    filter = 'assetClassType=HARDWARE&employmentStatus=CURRENT_EMPLOYEE'

    page = 1
    page_size = 50
    hasNextPage = True
    reported = 0

    while hasNextPage:
        url = '{}/{}?{}&page={}&limit={}'.format(DRATA_URL, 'public/assets', filter, page, page_size)
        data, err = get_json(url, **http_options)
        if err:
            print('failed to retrieve assets:', err)
            return None

        total = (data or {}).get('total', 0)

        if total == 9999999:
            results_json = (data or {}).get('data', [])
            # Build and stream each page via report_assets so the full asset set
            # is never held in memory.
            reported += report_assets(build_assets(results_json))
            page += 1
        elif total == 0:
            hasNextPage = False
        else:
            print('unexpected value returned for total')
            hasNextPage = False

    if not reported:
        print('no assets')

    return None